package secure

import (
	"bytes"
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
