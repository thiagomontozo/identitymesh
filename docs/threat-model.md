# Threat model

## Assets and trust boundaries

Assets include administrator sessions, connector service credentials, correlation links, lifecycle approvals, provider actions, observed access state, evidence and audit records. Trust boundaries exist at the browser/API, API/PostgreSQL, control plane/provider, CSV upload and notification egress.

## Threats and v0.1 mitigations

- **Stolen administrator session:** short expiration, revocation, HttpOnly/Secure/SameSite cookies, CSRF, origin checks, password change revocation, optional TOTP and audit.
- **Stolen connector token or LDAP credential:** AES-256-GCM at rest, external master key, redaction, least-privilege service accounts and no observed-user passwords.
- **Malicious connector administrator / SSRF:** permission checks, normalized fixed origin, HTTPS by default, blocked metadata/link-local destinations, cross-host redirect rejection, no arbitrary path/method/body or shell.
- **Privilege escalation / cross-organization access:** role permissions enforced server-side and organization derived from the authenticated session for every query and transition.
- **SCIM endpoint compromise or provider spoofing:** TLS verification, fixed endpoint, bounded response, post-write observation and evidence that identifies its source; trust cannot exceed provider authenticity.
- **LDAP compromise:** read-only API, secure bind options, scoped search base/filter, paging, timeout and TLS validation.
- **Stale or incomplete sync:** failures retain prior accounts, never convert omission into deletion, and force partial/inconclusive conclusions.
- **Mistaken correlation:** immutable identifiers first, trusted unique email policy, no name-only auto-link and auditable manual review.
- **Malicious CSV:** byte/row limits, strict known mapping, validation, preview/confirm separation and formula-safe exports.
- **Secret leakage:** structured logs omit request credentials, cookies, CSRF tokens, master key and provider secrets.
- **Audit tampering:** append-oriented tenant-scoped audit and optional evidence digests; no claim of tamper-proof storage.
- **Replayed lifecycle request / duplicate action:** explicit state machine, unique idempotency key, persisted attempts and desired-state re-read.
- **Provider partial failure:** bounded retries, no long database transaction, isolated connector failure and honest outcome status.

## Mass deprovisioning risk

Identity platforms can make high-impact bulk changes. v0.1 mitigates this with read-only connector defaults, per-person lifecycle cases, generated previews, separate approval, declared capability checks, bounded workers, audit, idempotency, no bulk delete and no destructive account deletion. A `Disable Everyone` operation does not exist.

## Residual risk

A compromised owner, database administrator, host or master key can cause substantial harm. Process-local rate limits do not coordinate across instances. Evidence integrity hashes do not prevent a privileged database attacker from rewriting both data and hashes. Production deployment requires independent threat review and operational controls.
