package config

import "testing"

func validEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("IDENTITYMESH_ENV", "production")
	t.Setenv("IDENTITYMESH_DATABASE_URL", "postgres://example")
	t.Setenv("IDENTITYMESH_SESSION_SECRET", "01234567890123456789012345678901")
	t.Setenv("IDENTITYMESH_SECRET_PROVIDER", "VAULT_TRANSIT")
	t.Setenv("IDENTITYMESH_VAULT_ADDR", "https://vault.example.test")
	t.Setenv("IDENTITYMESH_VAULT_TOKEN", "test-token")
	t.Setenv("IDENTITYMESH_ALLOWED_ORIGIN", "https://identitymesh.example.test")
	t.Setenv("IDENTITYMESH_SECURE_COOKIES", "true")
	t.Setenv("IDENTITYMESH_JOB_MODE", "DISTRIBUTED")
}

func TestProductionSafetyConfiguration(t *testing.T) {
	validEnvironment(t)
	if _, err := Load(); err != nil {
		t.Fatalf("valid production configuration rejected: %v", err)
	}
	t.Run("secure cookies", func(t *testing.T) {
		validEnvironment(t)
		t.Setenv("IDENTITYMESH_SECURE_COOKIES", "false")
		if _, err := Load(); err == nil {
			t.Fatal("production accepted insecure cookies")
		}
	})
	t.Run("https origin", func(t *testing.T) {
		validEnvironment(t)
		t.Setenv("IDENTITYMESH_ALLOWED_ORIGIN", "http://identitymesh.example.test")
		if _, err := Load(); err == nil {
			t.Fatal("production accepted an HTTP origin")
		}
	})
	t.Run("proxy CIDR", func(t *testing.T) {
		validEnvironment(t)
		t.Setenv("IDENTITYMESH_TRUSTED_PROXY_CIDRS", "not-a-network")
		if _, err := Load(); err == nil {
			t.Fatal("invalid proxy CIDR accepted")
		}
	})
}
