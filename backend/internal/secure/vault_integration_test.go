//go:build integration

package secure

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestRealVaultTransitRoundTrip(t *testing.T) {
	address := os.Getenv("IDENTITYMESH_TEST_VAULT_URL")
	if address == "" {
		t.Skip("IDENTITYMESH_TEST_VAULT_URL not configured")
	}
	call := func(method, path string, body any) int {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, address+path, bytes.NewReader(raw))
		req.Header.Set("X-Vault-Token", "identitymesh-test-only")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	status := call(http.MethodPost, "/v1/sys/mounts/transit", map[string]string{"type": "transit"})
	if status != http.StatusNoContent && status != http.StatusBadRequest {
		t.Fatalf("enable transit status=%d", status)
	}
	status = call(http.MethodPost, "/v1/transit/keys/identitymesh", map[string]any{"type": "aes256-gcm96", "derived": false})
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("create key status=%d", status)
	}
	store, err := NewVaultTransitStore(address, "identitymesh-test-only", "", "transit", "identitymesh", true, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := store.Encrypt([]byte("synthetic-provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := store.Decrypt(ciphertext)
	if err != nil || string(plain) != "synthetic-provider-token" {
		t.Fatalf("Vault roundtrip failed: plain=%q err=%v", plain, err)
	}
	if err = store.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}
