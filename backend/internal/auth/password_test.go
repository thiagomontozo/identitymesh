package auth

import (
	"testing"
	"time"
)

func TestArgon2idPasswordHash(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if encoded[:9] != "$argon2id" {
		t.Fatalf("unexpected encoding %q", encoded)
	}
	if !VerifyPassword(encoded, "correct horse battery staple") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(encoded, "wrong password") {
		t.Fatal("wrong password accepted")
	}
}
func TestTOTPRejectsInvalid(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyTOTP(secret, "000000", time.Unix(1000, 0)) && VerifyTOTP(secret, "111111", time.Unix(1000, 0)) {
		t.Fatal("invalid TOTP unexpectedly accepted")
	}
}
