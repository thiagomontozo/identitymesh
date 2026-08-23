package config

import (
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment          string
	HTTPAddr             string
	DatabaseURL          string
	AllowedOrigin        string
	SecureCookies        bool
	RequirePrivilegedMFA bool
	SessionSecret        string
	MasterKey            []byte
	MaxConcurrentSyncs   int
	MaxConcurrentActs    int
	SyncTimeout          time.Duration
	MaxCSVBytes          int64
	BootstrapEmail       string
	BootstrapPassword    string
}

func Load() (Config, error) {
	c := Config{
		Environment:        env("IDENTITYMESH_ENV", "development"),
		HTTPAddr:           env("IDENTITYMESH_HTTP_ADDR", ":8080"),
		DatabaseURL:        os.Getenv("IDENTITYMESH_DATABASE_URL"),
		AllowedOrigin:      env("IDENTITYMESH_ALLOWED_ORIGIN", "http://localhost:5173"),
		SessionSecret:      os.Getenv("IDENTITYMESH_SESSION_SECRET"),
		MaxConcurrentSyncs: envInt("IDENTITYMESH_MAX_CONCURRENT_SYNCS", 2),
		MaxConcurrentActs:  envInt("IDENTITYMESH_MAX_CONCURRENT_ACTIONS", 4),
		MaxCSVBytes:        envInt64("IDENTITYMESH_MAX_CSV_BYTES", 10<<20),
		BootstrapEmail:     os.Getenv("IDENTITYMESH_BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapPassword:  os.Getenv("IDENTITYMESH_BOOTSTRAP_ADMIN_PASSWORD"),
	}
	c.SecureCookies, _ = strconv.ParseBool(env("IDENTITYMESH_SECURE_COOKIES", "true"))
	c.RequirePrivilegedMFA, _ = strconv.ParseBool(env("IDENTITYMESH_REQUIRE_MFA_FOR_PRIVILEGED_ROLES", "false"))
	c.SyncTimeout, _ = time.ParseDuration(env("IDENTITYMESH_DEFAULT_SYNC_TIMEOUT", "30s"))
	if c.DatabaseURL == "" {
		return c, errors.New("IDENTITYMESH_DATABASE_URL is required")
	}
	if c.SessionSecret == "" || len(c.SessionSecret) < 32 {
		return c, errors.New("IDENTITYMESH_SESSION_SECRET must contain at least 32 bytes")
	}
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("IDENTITYMESH_MASTER_KEY"))
	if err != nil || len(raw) != 32 {
		return c, errors.New("IDENTITYMESH_MASTER_KEY must be a base64-encoded 32-byte key")
	}
	c.MasterKey = raw
	return c, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func envInt(key string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil || v < 1 {
		return fallback
	}
	return v
}
func envInt64(key string, fallback int64) int64 {
	v, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil || v < 1 {
		return fallback
	}
	return v
}
