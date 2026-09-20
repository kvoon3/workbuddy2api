package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"workbuddy2api/internal/apikey"
	"workbuddy2api/internal/auth"
	"workbuddy2api/internal/session"
	"workbuddy2api/internal/usage"
)

func keyRequest(h *Handler, method, path, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestKeyUsageIsolationAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	store, err := usage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	keys := []apikey.Key{{ID: "alice", Name: "Alice", Key: "alice-secret"}, {ID: "bob", Key: "bob-secret"}}
	h := NewHandler(Config{APIKey: "admin-secret", APIKeys: keys, Usage: store,
		Pool:     testPoolWith(&auth.Auth{UID: "u", AccessToken: "upstream", ExpiresAt: 9999999999}),
		Upstream: newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true }),
	})
	for _, tc := range []struct {
		key, body string
		code      int
	}{
		{"alice-secret", `{"model":"model-a","stream":true}`, 200},
		{"alice-secret", `{"model":"model-b","stream":false}`, 200},
		{"bob-secret", `{"model":"model-b"}`, 200},
		{"bob-secret", `{invalid`, 400},
		{"wrong-secret", `{"model":"model-a"}`, 401},
		{"", `{}`, 401},
	} {
		if w := keyRequest(h, "POST", "/v1/chat/completions", tc.key, tc.body); w.Code != tc.code {
			t.Fatalf("chat: %d %s", w.Code, w.Body)
		}
	}
	w := keyRequest(h, "GET", "/v1/usage/keys", "alice-secret", "")
	var result struct {
		Data []usage.Entry `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 1 {
		t.Fatalf("self leaked other keys: %s", w.Body)
	}
	a := result.Data[0]
	if a.ID != "alice" || a.Requests != 2 || a.Succeeded != 2 || a.Failed != 0 || a.Prompt != 2 || a.Completion != 2 || a.Total != 4 || a.StreamRequests != 1 || len(a.Models) != 2 {
		t.Fatalf("alice: %+v", a)
	}
	if w := keyRequest(h, "GET", "/v1/usage/keys?scope=all", "alice-secret", ""); w.Code != 403 {
		t.Fatalf("non-admin: %d", w.Code)
	}
	if w := keyRequest(h, "GET", "/v1/usage/keys?scope=bad", "alice-secret", ""); w.Code != 400 {
		t.Fatalf("bad scope: %d", w.Code)
	}
	w = keyRequest(h, "GET", "/v1/usage/keys?scope=all", "admin-secret", "")
	if w.Code != 200 {
		t.Fatalf("admin: %d %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 3 {
		t.Fatalf("all: %s", w.Body)
	}
	b := result.Data[1]
	if b.ID != "bob" || b.Requests != 2 || b.Succeeded != 1 || b.Failed != 1 || b.Total != 2 || b.UsageMissingRequests != 1 {
		t.Fatalf("bob: %+v", b)
	}
	if strings.Contains(w.Body.String(), "secret") {
		t.Fatal("credential leaked in response")
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	restored, err := usage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Rotation retains the identity's history; removal does not erase audit totals.
	keys[0].Key = "rotated-secret"
	h2 := NewHandler(Config{APIKey: "admin-secret", APIKeys: keys[:1], Usage: restored})
	if w := keyRequest(h2, "GET", "/v1/usage/keys", "alice-secret", ""); w.Code != 401 {
		t.Fatal("old credential accepted")
	}
	w = keyRequest(h2, "GET", "/v1/usage/keys", "rotated-secret", "")
	if !strings.Contains(w.Body.String(), `"requests":2`) {
		t.Fatalf("restore: %s", w.Body)
	}
	w = keyRequest(h2, "GET", "/v1/usage/keys?scope=all", "admin-secret", "")
	if !strings.Contains(w.Body.String(), `"id":"bob"`) {
		t.Fatal("removed key history missing")
	}
}

func TestKeyOnlyAuthAndOpenMode(t *testing.T) {
	for _, protected := range []bool{true, false} {
		cfg := Config{Pool: testPoolWith()}
		if protected {
			cfg.APIKeys = []apikey.Key{{ID: "ops", Key: "ops-secret", Admin: true}}
		}
		h := NewHandler(cfg)
		for _, path := range []string{"/v1/usage/keys", "/v1/usage", "/status", "/v1/models"} {
			want := 200
			if protected {
				want = 401
			}
			if w := keyRequest(h, "GET", path, "", ""); w.Code != want {
				t.Errorf("%s: %d want %d", path, w.Code, want)
			}
		}
		if w := keyRequest(h, "GET", "/healthz", "", ""); w.Code != 503 {
			t.Errorf("healthz: %d", w.Code)
		}
		if protected {
			if w := keyRequest(h, "GET", "/v1/usage/keys?scope=all", "ops-secret", ""); w.Code != 200 {
				t.Errorf("admin key: %d", w.Code)
			}
		} else {
			keyRequest(h, "POST", "/v1/chat/completions", "untrusted", `{}`)
			if e := h.cfg.Usage.Entries(nil); len(e) != 1 || e[0].ID != "anonymous" || e[0].Failed != 1 {
				t.Fatalf("open counters: %+v", e)
			}
		}
	}
}

func TestUsageCountsFinalRequestNotRetries(t *testing.T) {
	calls := 0
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		calls++
		if calls == 1 {
			return 500, `{"error":"retry"}`, false
		}
		return 200, sseOK, true
	})
	h := NewHandler(Config{Pool: testPoolWith(
		&auth.Auth{UID: "a", AccessToken: "a", ExpiresAt: 9999999999},
		&auth.Auth{UID: "b", AccessToken: "b", ExpiresAt: 9999999999}), Upstream: up})
	if w := keyRequest(h, "POST", "/v1/chat/completions", "", `{"model":"m"}`); w.Code != 200 {
		t.Fatal(w.Body)
	}
	e := h.cfg.Usage.Entries(nil)[0]
	if calls != 2 || e.Requests != 1 || e.Succeeded != 1 || e.Total != 2 {
		t.Fatalf("calls=%d entry=%+v", calls, e)
	}
}

func TestStreamAndSyncUsageOutcomes(t *testing.T) {
	for _, stream := range []bool{true, false} {
		for _, tc := range []struct {
			name, body     string
			success        bool
			total, missing int64
		}{
			{"normal", sseOK, true, 2, 0},
			{"missing", "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n", true, 0, 1},
			{"empty", "data: [DONE]\n\n", false, 0, 1},
			{"error", "data: {\"error\":{\"message\":\"failed\"}}\n\ndata: [DONE]\n\n", false, 0, 1},
			{"last_usage", "data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n\ndata: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\ndata: [DONE]\n\ndata: {\"usage\":{\"total_tokens\":999}}\n", true, 7, 0},
		} {
			t.Run(fmt.Sprintf("%s/stream=%v", tc.name, stream), func(t *testing.T) {
				h := NewHandler(Config{Pool: testPoolWith(&auth.Auth{UID: "u", ExpiresAt: 9999999999}), Upstream: newFakeUpstream(t, func(string) (int, string, bool) { return 200, tc.body, true })})
				w := keyRequest(h, "POST", "/v1/chat/completions", "", fmt.Sprintf(`{"model":"m","stream":%v}`, stream))
				e := h.cfg.Usage.Entries(nil)[0]
				if e.Requests != 1 || (e.Succeeded == 1) != tc.success || e.Total != tc.total || e.UsageMissingRequests != tc.missing {
					t.Fatalf("entry: %+v", e)
				}
				if tc.name == "error" && !strings.Contains(w.Body.String(), `"error"`) {
					t.Fatal("error frame lost")
				}
			})
		}
	}
}

func TestKeySessionIsolation(t *testing.T) {
	sess := session.New(session.Config{TTL: time.Hour})
	h := NewHandler(Config{APIKeys: []apikey.Key{{ID: "alice", Key: "a"}, {ID: "bob", Key: "b"}}, Session: sess,
		Pool:     testPoolWith(&auth.Auth{UID: "u", ExpiresAt: 9999999999}),
		Upstream: newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true }),
	})
	for _, key := range []string{"a", "b"} {
		if w := keyRequest(h, "POST", "/v1/chat/completions", key, `{"model":"m","conversation_id":"same"}`); w.Code != 200 {
			t.Fatal(w.Body)
		}
	}
	if sess.Count() != 2 {
		t.Fatalf("shared session binding: %d", sess.Count())
	}
}

type partialErrorReader struct{ read bool }

func (r *partialErrorReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	return copy(p, `data: {"usage":{"total_tokens":3}}`), errors.New("connection interrupted")
}

func TestStatsReaderPreservesPartialReadError(t *testing.T) {
	r := newChatStatsReaderSince(&partialErrorReader{}, time.Now())
	if _, err := io.ReadAll(r); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("read error lost: %v", err)
	}
}

type failedClientWriter struct{ header http.Header }

func (w *failedClientWriter) Header() http.Header       { return w.header }
func (w *failedClientWriter) WriteHeader(int)           {}
func (w *failedClientWriter) Write([]byte) (int, error) { return 0, errors.New("client disconnected") }

func TestClientWriteFailureCountsAsFailed(t *testing.T) {
	for _, stream := range []bool{true, false} {
		h := NewHandler(Config{Pool: testPoolWith(&auth.Auth{UID: "u", ExpiresAt: 9999999999}), Upstream: newFakeUpstream(t, func(string) (int, string, bool) { return 200, sseOK, true })})
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(fmt.Sprintf(`{"model":"m","stream":%v}`, stream)))
		h.ServeHTTP(&failedClientWriter{header: http.Header{}}, r)
		if e := h.cfg.Usage.Entries(nil)[0]; e.Failed != 1 || e.Succeeded != 0 {
			t.Fatalf("stream=%v: %+v", stream, e)
		}
	}
}

func TestInvalidBodiesCountOnceWithoutUpstream(t *testing.T) {
	h := NewHandler(Config{})
	for _, body := range []string{`null`, `[]`, `"text"`, `{"stream":"wrong"}`, strings.Repeat(" ", (8<<20)+1)} {
		w := keyRequest(h, "POST", "/v1/chat/completions", "", body)
		if w.Code != 400 && w.Code != 413 {
			t.Fatalf("invalid body status: %d", w.Code)
		}
	}
	if e := h.cfg.Usage.Entries(nil)[0]; e.Requests != 5 || e.Failed != 5 || e.UsageMissingRequests != 5 {
		t.Fatalf("invalid counters: %+v", e)
	}
}
