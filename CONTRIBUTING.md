# Contributing

IdentityMesh uses Go, PostgreSQL, React, TypeScript and Docker. Start with `docs/getting-started.md`, then read the architecture and security model before changing lifecycle or connector code.

Run `go test ./backend/...`, frontend lint/typecheck/tests/build, and the synthetic integration suite before opening a pull request. Connector changes must use typed protocol operations, fixed administrative origins, bounded responses/timeouts/retries, explicit capabilities and redacted logs. Provider calls must not occur inside long database transactions.

Never commit secrets, `.env`, private keys or real directory exports. Tests must not use real provider accounts, corporate LDAP, production tenants, real employees or personally identifiable fixtures. Names and credentials in fixtures must be wholly synthetic.

Correlation changes require tests proving that name-only matches do not auto-link. Lifecycle changes require preview, explicit approval, tenant isolation, idempotency and post-action observation. A provider success response must never be equated with verified access removal.
