package config

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	WebhookURL           string
	WebhookSecret        string
	SecretProvider       string
	VaultAddress         string
	VaultToken           string
	VaultNamespace       string
	VaultTransitMount    string
	VaultTransitKey      string
	JobMode              string
	WorkerID             string
	WorkerLease          time.Duration
	WorkerPollInterval   time.Duration
	TrustedProxyCIDRs    []string
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
		WebhookURL:         os.Getenv("IDENTITYMESH_WEBHOOK_URL"),
		WebhookSecret:      os.Getenv("IDENTITYMESH_WEBHOOK_SECRET"),
		SecretProvider:     env("IDENTITYMESH_SECRET_PROVIDER", "LOCAL_AES_GCM"),
		VaultAddress:       os.Getenv("IDENTITYMESH_VAULT_ADDR"),
		VaultToken:         os.Getenv("IDENTITYMESH_VAULT_TOKEN"),
		VaultNamespace:     os.Getenv("IDENTITYMESH_VAULT_NAMESPACE"),
		VaultTransitMount:  env("IDENTITYMESH_VAULT_TRANSIT_MOUNT", "transit"),
		VaultTransitKey:    env("IDENTITYMESH_VAULT_TRANSIT_KEY", "identitymesh"),
		JobMode:            env("IDENTITYMESH_JOB_MODE", "DISTRIBUTED"),
		WorkerID:           os.Getenv("IDENTITYMESH_WORKER_ID"),
	}
	c.SecureCookies, _ = strconv.ParseBool(env("IDENTITYMESH_SECURE_COOKIES", "true"))
	c.RequirePrivilegedMFA, _ = strconv.ParseBool(env("IDENTITYMESH_REQUIRE_MFA_FOR_PRIVILEGED_ROLES", "false"))
	var err error
	if c.SyncTimeout, err = time.ParseDuration(env("IDENTITYMESH_DEFAULT_SYNC_TIMEOUT", "30s")); err != nil || c.SyncTimeout <= 0 {
		return c, errors.New("IDENTITYMESH_DEFAULT_SYNC_TIMEOUT must be a positive duration")
	}
	if c.WorkerLease, err = time.ParseDuration(env("IDENTITYMESH_WORKER_LEASE", "2m")); err != nil || c.WorkerLease < 10*time.Second {
		return c, errors.New("IDENTITYMESH_WORKER_LEASE must be at least 10s")
	}
	if c.WorkerPollInterval, err = time.ParseDuration(env("IDENTITYMESH_WORKER_POLL_INTERVAL", "500ms")); err != nil || c.WorkerPollInterval < 50*time.Millisecond {
		return c, errors.New("IDENTITYMESH_WORKER_POLL_INTERVAL must be at least 50ms")
	}
	if raw := os.Getenv("IDENTITYMESH_TRUSTED_PROXY_CIDRS"); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			if value := strings.TrimSpace(item); value != "" {
				if _, _, parseErr := net.ParseCIDR(value); parseErr != nil {
					return c, errors.New("IDENTITYMESH_TRUSTED_PROXY_CIDRS contains an invalid CIDR")
				}
				c.TrustedProxyCIDRs = append(c.TrustedProxyCIDRs, value)
			}
		}
	}
	if c.DatabaseURL == "" {
		return c, errors.New("IDENTITYMESH_DATABASE_URL is required")
	}
	if c.SessionSecret == "" || len(c.SessionSecret) < 32 {
		return c, errors.New("IDENTITYMESH_SESSION_SECRET must contain at least 32 bytes")
	}
	if c.JobMode != "DISTRIBUTED" && c.JobMode != "INLINE" {
		return c, errors.New("IDENTITYMESH_JOB_MODE must be DISTRIBUTED or INLINE")
	}
	if c.Environment == "production" && c.JobMode != "DISTRIBUTED" {
		return c, errors.New("production requires IDENTITYMESH_JOB_MODE=DISTRIBUTED")
	}
	if c.Environment == "production" {
		origin, parseErr := url.Parse(c.AllowedOrigin)
		if parseErr != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil {
			return c, errors.New("production requires an HTTPS IDENTITYMESH_ALLOWED_ORIGIN")
		}
		if !c.SecureCookies {
			return c, errors.New("production requires IDENTITYMESH_SECURE_COOKIES=true")
		}
	}
	if c.SecretProvider == "VAULT_TRANSIT" {
		if c.VaultAddress == "" || c.VaultToken == "" {
			return c, errors.New("Vault address and token are required for VAULT_TRANSIT")
		}
	} else if c.SecretProvider == "LOCAL_AES_GCM" {
		raw, err := base64.StdEncoding.DecodeString(os.Getenv("IDENTITYMESH_MASTER_KEY"))
		if err != nil || len(raw) != 32 {
			return c, errors.New("IDENTITYMESH_MASTER_KEY must be a base64-encoded 32-byte key")
		}
		c.MasterKey = raw
	} else {
		return c, errors.New("IDENTITYMESH_SECRET_PROVIDER must be LOCAL_AES_GCM or VAULT_TRANSIT")
	}
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
