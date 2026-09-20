// Package usage persists per-key chat usage. It never stores credentials or prompts.
package usage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Tokens struct {
	Prompt     int64 `json:"prompt_tokens"`
	Completion int64 `json:"completion_tokens"`
	Total      int64 `json:"total_tokens"`
}

type Counters struct {
	Requests              int64 `json:"requests"`
	Succeeded             int64 `json:"succeeded"`
	Failed                int64 `json:"failed"`
	StreamRequests        int64 `json:"stream_requests"`
	UsageReportedRequests int64 `json:"usage_reported_requests"`
	UsageMissingRequests  int64 `json:"usage_missing_requests"`
	Tokens
	DurationMS int64 `json:"duration_ms"`
}

type Entry struct {
	ID string `json:"id"`
	Counters
	LastUsedAt time.Time           `json:"last_used_at,omitempty"`
	Models     map[string]Counters `json:"models"`
}

type Record struct {
	ID, Model                 string
	Success, Stream, HasUsage bool
	Tokens                    Tokens
	Duration                  time.Duration
}

type snapshot struct {
	Version int     `json:"version"`
	Keys    []Entry `json:"keys"`
}

type Store struct {
	mu              sync.RWMutex
	flushMu         sync.Mutex
	path            string
	keys            map[string]Entry
	revision, saved uint64
}

// Open refuses corrupt existing data so a restart cannot silently reset accounting.
// An empty path creates an in-memory store, useful for embedded use and tests.
func Open(path string) (*Store, error) {
	s := &Store{path: path, keys: map[string]Entry{}}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read usage: %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("decode usage: %w", err)
	}
	if snap.Version != 1 {
		return nil, fmt.Errorf("unsupported usage version %d", snap.Version)
	}
	for _, e := range snap.Keys {
		if _, exists := s.keys[e.ID]; e.ID == "" || exists {
			return nil, fmt.Errorf("invalid or duplicate usage identity")
		}
		if e.Models == nil {
			e.Models = map[string]Counters{}
		}
		s.keys[e.ID] = e
	}
	return s, nil
}

func (c *Counters) add(r Record) {
	c.Requests++
	if r.Success {
		c.Succeeded++
	} else {
		c.Failed++
	}
	if r.Stream {
		c.StreamRequests++
	}
	if r.HasUsage {
		c.UsageReportedRequests++
		c.Prompt += r.Tokens.Prompt
		c.Completion += r.Tokens.Completion
		c.Total += r.Tokens.Total
	} else {
		c.UsageMissingRequests++
	}
	c.DurationMS += r.Duration.Milliseconds()
}

func (s *Store) Record(r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.keys[r.ID]
	e.ID = r.ID
	if e.Models == nil {
		e.Models = map[string]Counters{}
	}
	e.Counters.add(r)
	c := e.Models[r.Model]
	c.add(r)
	e.Models[r.Model] = c
	e.LastUsedAt = time.Now().UTC()
	s.keys[r.ID] = e
	s.revision++
}

// Entries returns detached snapshots. Requested IDs include zero-usage entries;
// nil returns all historical identities, including removed keys.
func (s *Store) Entries(ids []string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ids == nil {
		ids = make([]string, 0, len(s.keys))
		for id := range s.keys {
			ids = append(ids, id)
		}
	}
	out := make([]Entry, 0, len(ids))
	for _, id := range ids {
		e := s.keys[id]
		e.ID = id
		models := make(map[string]Counters, len(e.Models))
		for m, c := range e.Models {
			models[m] = c
		}
		e.Models = models
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Flush serializes snapshots via atomic replacement; failed writes stay dirty for retry.
func (s *Store) Flush() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.RLock()
	rev := s.revision
	clean := s.path == "" || rev == s.saved
	s.mu.RUnlock()
	if clean {
		return nil
	}
	raw, err := json.Marshal(snapshot{Version: 1, Keys: s.Entries(nil)})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".usage-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	s.mu.Lock()
	s.saved = rev
	s.mu.Unlock()
	return nil
}
