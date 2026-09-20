package usage

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentRecordFlushAndRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "usage.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Record(Record{ID: "alice", Model: "model", Success: true, Stream: true, HasUsage: true, Tokens: Tokens{2, 3, 5}, Duration: time.Millisecond})
			_ = s.Entries(nil)
			if err := s.Flush(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	s.Record(Record{ID: "bob", Model: "other"})
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := restored.Entries(nil)
	if len(entries) != 2 {
		t.Fatalf("entries: %+v", entries)
	}
	a := entries[0]
	if a.ID != "alice" || a.Requests != 80 || a.Succeeded != 80 || a.Total != 400 || a.Prompt != 160 || a.Completion != 240 || a.StreamRequests != 80 || a.DurationMS != 80 || a.UsageReportedRequests != 80 || a.LastUsedAt.IsZero() {
		t.Fatalf("alice: %+v", a)
	}
	if a.Models["model"] != a.Counters {
		t.Fatal("model totals mismatch")
	}
	if b := entries[1]; b.ID != "bob" || b.Failed != 1 || b.UsageMissingRequests != 1 {
		t.Fatalf("bob: %+v", b)
	}
	entries[0].Models["model"] = Counters{}
	if restored.Entries([]string{"alice"})[0].Models["model"].Requests != 80 {
		t.Fatal("snapshot aliases internal map")
	}
	if zero := restored.Entries([]string{"unused"})[0]; zero.ID != "unused" || zero.Requests != 0 || zero.Models == nil {
		t.Fatalf("zero: %+v", zero)
	}
}

func TestCorruptStoreAndFlushRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	for _, raw := range []string{`broken`, `{"version":2}`, `{"version":1,"keys":[{"id":"a"},{"id":"a"}]}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err == nil {
			t.Fatal("accepted corrupt data")
		}
	}
	parent := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(parent, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := Open("")
	s.path = filepath.Join(parent, "usage.json")
	s.Record(Record{ID: "a", Model: "m"})
	if err := s.Flush(); err == nil {
		t.Fatal("expected write failure")
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil || !strings.Contains(string(raw), `"requests":1`) {
		t.Fatalf("retry: %s, %v", raw, err)
	}
}
