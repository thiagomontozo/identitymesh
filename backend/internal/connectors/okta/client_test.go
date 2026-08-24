package okta

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOktaSuspendIsIdempotent(t *testing.T) {
	status := "ACTIVE"
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS synthetic" {
			t.Fatal("missing SSWS token")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/users/u1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1", "status": status, "profile": map[string]any{"login": "u1@example.test", "email": "u1@example.test"}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/users/u1/lifecycle/suspend":
			calls++
			status = "SUSPENDED"
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic", true, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.DisableUser(t.Context(), "u1"); e != nil {
		t.Fatal(e)
	}
	if e = c.DisableUser(t.Context(), "u1"); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatalf("suspend calls=%d", calls)
	}
}
