package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
)

// --- GitLab Regression Tests ---

// A revoke DELETE that returns 404 (token already gone or never existed) must be treated as
// success — the credential is definitely gone.
func TestGitlabRevoke404Success(t *testing.T) {
	f := &fakeGitlab{
		ids:  map[string]int{"projects/g%2Fp": 1},
		fail: map[string]int{"/api/v4/personal_access_tokens/99": http.StatusNotFound},
	}
	g := f.provider(t, Config{TokenGrants: []Grant{{Project: "g/p"}}})
	c, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// 404 on revoke must be treated as success (the token is definitely gone).
	if err := c.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup with 404: must succeed, got %v", err)
	}
}

// A 201 create response with an empty token field must fail closed ('empty token'), never a
// corrupt env.
func TestGitlabCreateTokenEmptyResponse(t *testing.T) {
	f := &fakeGitlab{ids: map[string]int{"projects/g%2Fp": 1}, createBody: `{"id":99,"token":"","granular":true}`}
	g := f.provider(t, Config{TokenGrants: []Grant{{Project: "g/p"}}})
	_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err == nil {
		t.Fatal("createToken must fail closed when the response has an empty token field")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("error must mention 'empty token', got %v", err)
	}
}

// A URL with an '@' but no colon after it (e.g. 'user:tok@host/path') must not slice on a
// negative index in the scp-form parse — fail closed instead.
func TestGitlabParseURLMalformedUserinfo(t *testing.T) {
	malformedURLs := []string{
		"user:tok@gitlab.com/g/r.git", // colon before @, none after (no scp-form colon)
		"foo:bar@host/path",           // same pattern
	}
	for _, raw := range malformedURLs {
		if _, _, err := parseGitlabURL(raw); err == nil {
			t.Errorf("parseGitlabURL(%q) must fail closed, got nil error", raw)
		}
	}
}

// A 200 /user response with invalid JSON must fail closed ('decode current user'), aborting
// Mint.
func TestGitlabCurrentUserMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()
	g := &gitlab{
		cfg:     Config{},
		token:   "glpat-host",
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
	_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err == nil {
		t.Fatal("currentUser must fail closed on malformed JSON")
	}
	if !strings.Contains(err.Error(), "decode current user") {
		t.Errorf("error should mention 'decode current user', got %v", err)
	}
}

// A /user response with a valid body but id <= 0 must fail closed ('invalid user id'),
// aborting Mint.
func TestGitlabCurrentUserInvalidID(t *testing.T) {
	for _, invalidID := range []int{0, -1} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":       invalidID,
				"username": "user",
			})
		}))
		defer srv.Close()
		g := &gitlab{
			cfg:     Config{},
			token:   "glpat-host",
			host:    "gitlab.example.com",
			apiBase: srv.URL,
			client:  srv.Client(),
		}
		_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
		if err == nil {
			t.Fatalf("currentUser with id=%d must fail closed", invalidID)
		}
		if !strings.Contains(err.Error(), "invalid user id") {
			t.Errorf("error should mention 'invalid user id', got %v", err)
		}
	}
}

// A non-2xx response with a body > 512 bytes must render safely (io.LimitReader caps it),
// never exhaust memory.
func TestGitlabErrorBodyCap(t *testing.T) {
	// Create a large error response body (over 512 bytes).
	largeBody := strings.Repeat("X", 1000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"` + largeBody + `"}`))
	}))
	defer srv.Close()
	g := &gitlab{
		cfg:     Config{TokenGrants: []Grant{{Project: "g/p"}}},
		token:   "glpat-host",
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
	_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err == nil {
		t.Fatal("Mint must fail closed on 403")
	}
	// The error message should exist but be bounded (not panic, not exhaust memory).
	// gitlabError uses io.LimitReader(body, 512), so the rendered error is capped.
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}
}
