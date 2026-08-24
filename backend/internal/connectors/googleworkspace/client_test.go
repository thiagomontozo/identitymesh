package googleworkspace

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGoogleWorkspaceSuspend(t *testing.T) {
	suspended := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/directory/v1/users/u1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1", "primaryEmail": "u1@example.test", "suspended": suspended, "name": map[string]string{"fullName": "User One"}})
		case r.Method == http.MethodPatch && r.URL.Path == "/admin/directory/v1/users/u1":
			suspended = true
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic", "my_customer", true, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.DisableUser(t.Context(), "u1"); e != nil {
		t.Fatal(e)
	}
	u, e := c.GetUser(t.Context(), "u1")
	if e != nil || u.Active {
		t.Fatalf("active=%v err=%v", u.Active, e)
	}
}
