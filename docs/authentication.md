# Authentication

Passwords are hashed with Argon2id using per-password random salt, 64 MiB memory, three iterations and two lanes. Bootstrap credentials are supplied by environment and never hardcoded. Production bootstrap should be a one-time controlled operation followed by password rotation and MFA enrollment.

Opaque session tokens are random and stored only as SHA-256 hashes. Session cookies are HttpOnly and become Secure under HTTPS. Sessions expire, can be listed and individually revoked by their owner, and all of a user's sessions are revoked after password change. Mutating requests require a separate per-session CSRF value.

TOTP uses 30-second steps and a narrow clock window. Enrollment, confirmation and authenticator-code login are available in the web application. Set `IDENTITYMESH_REQUIRE_MFA_FOR_PRIVILEGED_ROLES=true` to reject login for OWNER, IDENTITY_ADMIN, SECURITY_ADMIN and OPERATOR users who have not enabled TOTP. Enroll bootstrap administrators before enabling this policy; it is disabled in the disposable development compose environment.
