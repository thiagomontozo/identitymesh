// TEST / DEMO ONLY. This intentionally small SCIM subset is not an identity provider.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	Schemas     []string         `json:"schemas,omitempty"`
	ID          string           `json:"id"`
	ExternalID  string           `json:"externalId,omitempty"`
	UserName    string           `json:"userName"`
	DisplayName string           `json:"displayName"`
	Active      bool             `json:"active"`
	Emails      []map[string]any `json:"emails,omitempty"`
	Meta        map[string]any   `json:"meta,omitempty"`
}
type Group struct {
	Schemas     []string            `json:"schemas,omitempty"`
	ID          string              `json:"id"`
	DisplayName string              `json:"displayName"`
	Members     []map[string]string `json:"members,omitempty"`
}
type server struct {
	mu      sync.RWMutex
	users   map[string]*User
	groups  map[string]*Group
	mode    string
	patches int
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:8090/health")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		resp.Body.Close()
		return
	}
	s := &server{users: map[string]*User{}, groups: map[string]*Group{}}
	s.seed()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "purpose": "TEST / DEMO ONLY"})
	})
	mux.HandleFunc("GET /scim/v2/Users", s.listUsers)
	mux.HandleFunc("GET /scim/v2/Users/{id}", s.getUser)
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", s.patchUser)
	mux.HandleFunc("GET /scim/v2/Groups", s.listGroups)
	mux.HandleFunc("GET /scim/v2/Groups/{id}", s.getGroup)
	mux.HandleFunc("POST /__test/mode/{mode}", s.setMode)
	mux.HandleFunc("POST /__test/reset", s.reset)
	mux.HandleFunc("GET /__test/state", s.state)
	addr := env("MOCK_SCIM_ADDR", ":8090")
	slog.Info("TEST / DEMO ONLY mock SCIM started", "address", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("mock SCIM stopped", "error", err.Error())
		os.Exit(1)
	}
}
func (s *server) seed() {
	now := time.Now().UTC().Format(time.RFC3339)
	for _, u := range []*User{{ID: "alex-a", ExternalID: "E1001", UserName: "alex.morgan", DisplayName: "Alex Morgan", Active: true, Emails: []map[string]any{{"value": "alex.morgan@identitymesh.test", "primary": true}}, Meta: map[string]any{"lastModified": now}}, {ID: "jordan-a", ExternalID: "E1002", UserName: "jordan.lee", DisplayName: "Jordan Lee", Active: true, Emails: []map[string]any{{"value": "jordan.lee@identitymesh.test", "primary": true}}, Meta: map[string]any{"lastModified": now}}, {ID: "orphan-legacy", UserName: "legacy.contractor", DisplayName: "Legacy Contractor", Active: true, Emails: []map[string]any{{"value": "legacy.contractor@external.test", "primary": true}}, Meta: map[string]any{"lastModified": now}}, {ID: "ambiguous", UserName: "taylor.other", DisplayName: "Taylor Silva", Active: true, Emails: []map[string]any{{"value": "someone.else@external.test", "primary": true}}, Meta: map[string]any{"lastModified": now}}} {
		u.Schemas = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}
		s.users[u.ID] = u
	}
	g := &Group{Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, ID: "admins", DisplayName: "Cloud App Administrators", Members: []map[string]string{{"value": "alex-a"}}}
	s.groups[g.ID] = g
}
func (s *server) failure(w http.ResponseWriter, r *http.Request) bool {
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()
	switch mode {
	case "500":
		http.Error(w, "synthetic provider failure", 500)
		return true
	case "timeout":
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
		return true
	case "rate-limit":
		w.Header().Set("Retry-After", "1")
		http.Error(w, "synthetic rate limit", 429)
		return true
	case "malformed":
		w.Header().Set("Content-Type", "application/scim+json")
		_, _ = w.Write([]byte(`{"Resources":[`))
		return true
	}
	return false
}
func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	if s.failure(w, r) {
		return
	}
	start, count := paging(r)
	s.mu.RLock()
	items := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		clone := *u
		if s.mode == "stale" {
			clone.Meta = map[string]any{"lastModified": "2020-01-01T00:00:00Z"}
		}
		items = append(items, &clone)
	}
	s.mu.RUnlock()
	end := start - 1 + count
	if end > len(items) {
		end = len(items)
	}
	page := []*User{}
	if start-1 < len(items) {
		page = items[start-1 : end]
	}
	writeSCIM(w, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(items), "startIndex": start, "itemsPerPage": len(page), "Resources": page})
}
func (s *server) getUser(w http.ResponseWriter, r *http.Request) {
	if s.failure(w, r) {
		return
	}
	s.mu.RLock()
	u, ok := s.users[r.PathValue("id")]
	mode := s.mode
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	clone := *u
	if mode == "inconsistent" {
		clone.Active = true
	}
	writeSCIM(w, clone)
}
func (s *server) patchUser(w http.ResponseWriter, r *http.Request) {
	if s.failure(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[r.PathValue("id")]
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	s.patches++
	if s.mode == "patch-failure" {
		http.Error(w, "synthetic PATCH failure", 500)
		return
	}
	if s.mode != "patch-success-no-change" && s.mode != "inconsistent" {
		u.Active = false
		u.Meta["lastModified"] = time.Now().UTC().Format(time.RFC3339)
	}
	w.WriteHeader(204)
}
func (s *server) listGroups(w http.ResponseWriter, r *http.Request) {
	if s.failure(w, r) {
		return
	}
	s.mu.RLock()
	items := make([]*Group, 0, len(s.groups))
	for _, g := range s.groups {
		items = append(items, g)
	}
	s.mu.RUnlock()
	start, count := paging(r)
	end := start - 1 + count
	if end > len(items) {
		end = len(items)
	}
	page := []*Group{}
	if start-1 < len(items) {
		page = items[start-1 : end]
	}
	writeSCIM(w, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(items), "startIndex": start, "itemsPerPage": len(page), "Resources": page})
}
func (s *server) getGroup(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	g, ok := s.groups[r.PathValue("id")]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	writeSCIM(w, g)
}
func (s *server) setMode(w http.ResponseWriter, r *http.Request) {
	mode := r.PathValue("mode")
	valid := map[string]bool{"normal": true, "500": true, "timeout": true, "rate-limit": true, "stale": true, "patch-failure": true, "patch-success-no-change": true, "inconsistent": true, "malformed": true}
	if !valid[mode] {
		http.Error(w, "unknown synthetic mode", 400)
		return
	}
	s.mu.Lock()
	if mode == "normal" {
		s.mode = ""
	} else {
		s.mode = mode
	}
	s.mu.Unlock()
	w.WriteHeader(204)
}
func (s *server) reset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.users = map[string]*User{}
	s.groups = map[string]*Group{}
	s.mode = ""
	s.patches = 0
	s.seed()
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
func (s *server) state(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeSCIM(w, map[string]any{"mode": s.mode, "patches": s.patches, "users": s.users})
}
func paging(r *http.Request) (int, int) {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if start < 1 {
		start = 1
	}
	if count < 1 || count > 200 {
		count = 100
	}
	return start, count
}
func writeSCIM(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(v)
}
func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
