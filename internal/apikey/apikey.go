// Package apikey defines gateway credentials and their non-secret identities.
package apikey

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"regexp"
	"strings"
)

type Key struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Key   string `json:"key"`
	Admin bool   `json:"admin,omitempty"`
}

type Identity struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Admin bool   `json:"admin"`
}

var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// Validate fails closed on ambiguous or unusable credentials, without logging secrets.
func Validate(legacy string, keys []Key) error {
	seenIDs := map[string]bool{"legacy": true, "anonymous": true}
	seenKeys := map[string]bool{}
	if legacy != "" {
		if strings.TrimSpace(legacy) != legacy || strings.ContainsAny(legacy, "\r\n\t ") {
			return fmt.Errorf("api_key must not contain whitespace")
		}
		seenKeys[legacy] = true
	}
	for i, k := range keys {
		if !validID.MatchString(k.ID) || seenIDs[k.ID] {
			return fmt.Errorf("api_keys[%d].id must be unique, non-reserved and contain 1-64 letters, digits, underscores or hyphens", i)
		}
		if k.Key == "" || strings.ContainsAny(k.Key, "\r\n\t ") || strings.TrimSpace(k.Key) != k.Key || seenKeys[k.Key] {
			return fmt.Errorf("api_keys[%d].key must be nonempty, unique and contain no whitespace", i)
		}
		seenIDs[k.ID], seenKeys[k.Key] = true, true
	}
	return nil
}

type credential struct {
	digest   [32]byte
	identity Identity
}

type Authenticator struct{ credentials []credential }

func New(legacy string, keys []Key) (*Authenticator, error) {
	if err := Validate(legacy, keys); err != nil {
		return nil, err
	}
	a := &Authenticator{}
	if legacy != "" {
		a.credentials = append(a.credentials, credential{sha256.Sum256([]byte(legacy)), Identity{ID: "legacy", Name: "Legacy API key", Admin: true}})
	}
	for _, k := range keys {
		a.credentials = append(a.credentials, credential{sha256.Sum256([]byte(k.Key)), Identity{ID: k.ID, Name: k.Name, Admin: k.Admin}})
	}
	return a, nil
}

func (a *Authenticator) Authenticate(header string) (Identity, bool) {
	if len(a.credentials) == 0 {
		return Identity{ID: "anonymous"}, true
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return Identity{}, false
	}
	digest := sha256.Sum256([]byte(parts[1]))
	var identity Identity
	matched := false
	for _, c := range a.credentials {
		if subtle.ConstantTimeCompare(digest[:], c.digest[:]) == 1 {
			identity, matched = c.identity, true
		}
	}
	return identity, matched
}

func (a *Authenticator) Identities() []Identity {
	out := make([]Identity, 0, len(a.credentials))
	for _, c := range a.credentials {
		out = append(out, c.identity)
	}
	if len(out) == 0 {
		out = append(out, Identity{ID: "anonymous"})
	}
	return out
}
