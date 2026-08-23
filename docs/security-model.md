# Security model

IdentityMesh assumes administrators and connector credentials are high-value targets. Controls use least privilege, explicit capabilities, read-only defaults, per-person plans, separate approval, bounded concurrency, immutable intent, idempotency, post-write observation and tenant-scoped audit.

Administrative authentication uses Argon2id password hashes and opaque server sessions whose tokens are hashed at rest. Cookies are HttpOnly, Secure in HTTPS environments and SameSite Lax. Mutations require a per-session CSRF token and valid origin. TOTP primitives support MFA policy for privileged roles; deployments must enable and operationally enforce that policy.

Connector service credentials are AES-256-GCM encrypted with an externally supplied 32-byte master key. Secrets are never returned in connector responses or written to logs. The local store is an abstraction boundary for future Vault and cloud secret managers.
