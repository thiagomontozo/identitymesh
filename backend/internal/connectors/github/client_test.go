package githubconnector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGitHubRemovesOrganizationMembership(t *testing.T) {
	active := true
	deletes := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/user/42":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octocat"})
		case r.Method == http.MethodGet && r.URL.Path == "/orgs/acme/memberships/octocat":
			state := "inactive"
			if active {
				state = "active"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"state": state, "user": map[string]any{"id": 42, "login": "octocat"}})
		case r.Method == http.MethodDelete && r.URL.Path == "/orgs/acme/members/octocat":
			active = false
			deletes++
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic", "acme", true, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.RemoveMembership(t.Context(), "", "42"); e != nil {
		t.Fatal(e)
	}
	if e = c.RemoveMembership(t.Context(), "", "42"); e != nil {
		t.Fatal(e)
	}
	if deletes != 1 {
		t.Fatalf("delete calls=%d", deletes)
	}
}
