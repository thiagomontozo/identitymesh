package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPaginationDisableAndReadAfterWrite(t *testing.T) {
	active := true
	var pages int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /scim/v2/Users", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pages, 1)
		start := r.URL.Query().Get("startIndex")
		resources := []map[string]any{{"id": "u1", "userName": "alex", "active": active}}
		if start == "2" {
			resources = []map[string]any{{"id": "u2", "userName": "jordan", "active": true}}
		}
		startNumber := 1
		if start == "2" {
			startNumber = 2
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": 2, "startIndex": startNumber, "itemsPerPage": 1, "Resources": resources})
	})
	mux.HandleFunc("PATCH /scim/v2/Users/u1", func(w http.ResponseWriter, r *http.Request) { active = false; w.WriteHeader(204) })
	mux.HandleFunc("GET /scim/v2/Users/u1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": "u1", "userName": "alex", "active": active})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client, err := New(srv.URL+"/scim/v2", "", true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	users, err := client.ListUsers(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || atomic.LoadInt32(&pages) != 2 {
		t.Fatalf("pagination failed: users=%d pages=%d", len(users), pages)
	}
	if err = client.DisableUser(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	u, err := client.GetUser(context.Background(), "u1")
	if err != nil || u.Active {
		t.Fatalf("post-write read did not confirm disabled: %+v %v", u, err)
	}
}
func TestRetryOnRateLimitIsBounded(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(429)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"totalResults": 0, "Resources": []any{}})
	}))
	defer srv.Close()
	client, _ := New(srv.URL, "", true, 2*time.Second)
	if _, err := client.ListUsers(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("got %d attempts, want 3", attempts)
	}
}
func TestRejectsUnsafeBaseURLsAndIDs(t *testing.T) {
	if _, err := New("http://169.254.169.254/latest", "", true, time.Second); err == nil {
		t.Fatal("metadata endpoint should be blocked")
	}
	if _, err := New("http://[fe80::1]/scim/v2", "", true, time.Second); err == nil {
		t.Fatal("IPv6 link-local endpoint should be blocked")
	}
	if _, err := New("https://metadata.google.internal/scim/v2", "", false, time.Second); err == nil {
		t.Fatal("metadata hostname should be blocked")
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	client, _ := New(srv.URL, "", true, time.Second)
	if _, err := client.GetUser(context.Background(), "../admin"); err == nil {
		t.Fatal("unsafe identifier accepted")
	}
}
