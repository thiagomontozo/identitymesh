package secure

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAESGCMRoundTripAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	store, _ := NewAESGCMStore(key)
	ciphertext, err := store.Encrypt([]byte("synthetic-scim-token"))
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "synthetic-scim-token" {
		t.Fatal("secret was not encrypted")
	}
	plain, err := store.Decrypt(ciphertext)
	if err != nil || string(plain) != "synthetic-scim-token" {
		t.Fatalf("roundtrip failed: %v", err)
	}
	wrong, _ := NewAESGCMStore(bytes.Repeat([]byte{8}, 32))
	if _, err = wrong.Decrypt(ciphertext); err == nil {
		t.Fatal("wrong master key must fail")
	}
	if _, err = store.Decrypt("not ciphertext"); err == nil {
		t.Fatal("malformed ciphertext must fail")
	}
}

func TestVaultTransitStoreRoundTrip(t *testing.T) {
	var tokenSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenSeen = r.Header.Get("X-Vault-Token") == "test-token"
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/encrypt/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:synthetic"}})
			return
		}
		if body["ciphertext"] != "vault:v1:synthetic" {
			t.Fatalf("unexpected ciphertext: %q", body["ciphertext"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("secret"))}})
	}))
	defer server.Close()
	store, err := NewVaultTransitStore(server.URL, "test-token", "team-a", "transit", "identitymesh", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := store.Encrypt([]byte("secret"))
	if err != nil || ciphertext != "vault:v1:synthetic" {
		t.Fatalf("encrypt: ciphertext=%q err=%v", ciphertext, err)
	}
	plain, err := store.Decrypt(ciphertext)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("decrypt: plaintext=%q err=%v", plain, err)
	}
	if !tokenSeen {
		t.Fatal("Vault token was not sent through the protected header")
	}
}

func TestVaultTransitStoreRejectsUnsafeConfiguration(t *testing.T) {
	for _, tc := range []struct{ address, mount, key string }{
		{"http://vault.example", "transit", "identitymesh"},
		{"https://vault.example?token=x", "transit", "identitymesh"},
		{"https://vault.example", "../transit", "identitymesh"},
		{"https://vault.example", "transit", "../key"},
	} {
		if _, err := NewVaultTransitStore(tc.address, "token", "", tc.mount, tc.key, false, 0); err == nil {
			t.Fatalf("unsafe Vault configuration accepted: %#v", tc)
		}
	}
}
