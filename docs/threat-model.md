# Threat model

## Assets and boundaries

Assets include administrator sessions, connector credentials, links, approvals, provider actions, observed state, evidence, durable jobs and audit. Boundaries exist at browser/API, ingress/proxy, API/PostgreSQL, API/Vault, worker/provider, CSV upload, LDAP and webhook egress.

## Principal threats and controls

- **Stolen administrator session:** expiry/revocation, HttpOnly/Secure/SameSite cookies, CSRF/origin checks, password-change revocation, optional required TOTP and audit.
- **Connector/Vault token theft:** encrypted opaque storage, redaction, external injection, least-privilege policy and no observed-user passwords. Vault tokens should be short-lived workload credentials.
- **Malicious connector admin/SSRF:** server authorization, fixed validated origins, HTTPS default, metadata/link-local denial, trusted redirects only, typed paths/methods/bodies and no shell.
- **Privilege escalation/cross-tenant access:** server-side permissions and organization derived from the session on reads, writes, links, actions, evidence, jobs and audit.
- **Provider spoofing/compromise:** TLS validation, fixed origin, bounded HTTP, explicit capabilities and post-write observation. Evidence trust cannot exceed provider authenticity.
- **LDAP compromise/unsafe write:** LDAPS support, scoped bind/search, whitelisted disable/membership strategies, no arbitrary modify/delete/password operation and post-write read.
- **Stale/incomplete sync:** failures retain earlier observations and force partial/inconclusive outcomes; failed discovery never implies deletion.
- **Mistaken correlation:** immutable identifiers first, trusted unique email policy, no name-only auto-link and audited manual decisions.
- **Malicious CSV:** byte/row limits, UTF-8/parser validation, preview/confirm and spreadsheet-formula-safe exports.
- **Replay/duplicate action:** state machine, unique action and job idempotency keys, leases, bounded attempts and desired-state pre-read.
- **Worker crash/partition:** expiring leases, heartbeat, reclaim, bounded retry and dead-letter state. Remote actions remain semantically idempotent and are verified afterward.
- **Distributed limiter bypass:** atomic PostgreSQL windows, hashed keys and proxy headers trusted only from configured CIDRs. Protected operations fail closed on limiter failure.
- **Vault/HSM outage:** readiness removes affected replicas; ciphertext remains opaque. Operators must provide Vault HA/recovery and avoid fail-open fallback.
- **Audit/evidence tampering:** append-oriented tenant-scoped records and SHA-256 metadata help detect unintended changes but are not tamper-proof against a privileged database operator.

## Mass deprovisioning risk

Identity platforms can make high-impact changes. IdentityMesh uses read-only defaults, per-person cases, generated preview, separate approval, declared capabilities, bounded local/provider concurrency, durable idempotency, audit, no bulk disable and no destructive account deletion.

## Residual risk

A compromised owner, database administrator, Vault control plane or provider administrator can cause substantial harm. HSM protection does not fix malicious authorized use. Production requires provider-side least privilege, dual-control operating procedures, monitoring, backup/restore drills, environment-specific load/failover tests and an independent threat review.
