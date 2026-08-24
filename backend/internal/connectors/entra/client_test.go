package entra

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEntraDiscoveryPaginationAndDisable(t *testing.T) {
	enabled := true
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Fatal("missing bearer token")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/users" && r.URL.Query().Get("page") == "2":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]any{"id": "u2", "userPrincipalName": "two@example.test", "displayName": "Two", "accountEnabled": true}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/users":
			if r.URL.Query().Get("$top") == "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]any{"id": "u1", "userPrincipalName": "one@example.test", "displayName": "One", "accountEnabled": enabled}}, "@odata.nextLink": serverURL(r) + "/v1.0/users?page=2"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/users/u1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1", "userPrincipalName": "one@example.test", "accountEnabled": enabled})
		case r.Method == http.MethodPatch && r.URL.Path == "/v1.0/users/u1":
			enabled = false
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/groups":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c, err := New(server.URL, "synthetic", true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	users, err := c.ListUsers(t.Context())
	if err != nil || len(users) != 2 {
		t.Fatalf("users=%d err=%v", len(users), err)
	}
	if err = c.DisableUser(t.Context(), "u1"); err != nil {
		t.Fatal(err)
	}
	u, err := c.GetUser(t.Context(), "u1")
	if err != nil || u.Active {
		t.Fatalf("post-write active=%v err=%v", u.Active, err)
	}
}
func serverURL(r *http.Request) string { return "http://" + r.Host }
