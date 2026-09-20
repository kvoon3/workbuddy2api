package apikey

import "testing"

func TestAuthenticate(t *testing.T) {
	a, err := New("old-secret", []Key{{ID: "alice", Key: "alice-secret"}, {ID: "ops", Key: "ops-secret", Admin: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		header, id string
		admin, ok  bool
	}{
		{"Bearer old-secret", "legacy", true, true},
		{"bearer alice-secret", "alice", false, true},
		{"Bearer ops-secret", "ops", true, true},
		{"", "", false, false}, {"Basic alice-secret", "", false, false},
		{"Bearer wrong", "", false, false}, {"Bearer alice-secret extra", "", false, false},
	} {
		got, ok := a.Authenticate(tc.header)
		if ok != tc.ok || got.ID != tc.id || got.Admin != tc.admin {
			t.Errorf("authentication got %+v/%v, want %s/%v", got, ok, tc.id, tc.ok)
		}
	}
	open, _ := New("", nil)
	if got, ok := open.Authenticate("Bearer arbitrary"); !ok || got.ID != "anonymous" || got.Admin {
		t.Fatalf("open identity: %+v/%v", got, ok)
	}
}

func TestRejectInvalidConfiguration(t *testing.T) {
	for _, keys := range [][]Key{
		{{ID: "", Key: "secret"}}, {{ID: "legacy", Key: "secret"}},
		{{ID: "anonymous", Key: "secret"}}, {{ID: "a:b", Key: "secret"}},
		{{ID: "a", Key: ""}}, {{ID: "a", Key: "bad key"}},
		{{ID: "a", Key: "same"}, {ID: "b", Key: "same"}},
		{{ID: "a", Key: "one"}, {ID: "a", Key: "two"}},
		{{ID: "a", Key: "old-secret"}},
	} {
		if _, err := New("old-secret", keys); err == nil {
			t.Error("invalid configuration accepted")
		}
	}
}
