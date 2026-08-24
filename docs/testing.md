# Testing

Unit tests prioritize lifecycle state machines, honest verification, deterministic correlation/no name-only link, RBAC, Argon2id, CSV safety, capability validation, bounded retry, native provider pagination/disable/read-after-write, LDAP write strategies, Vault failures and worker behavior.

Integration tests run against real isolated PostgreSQL, two Go SCIM providers, OpenLDAP and Vault. They cover migrations, tenant isolation, durable job claim/idempotency across two worker instances, rate-limit coordination across two limiter instances, SCIM failures/retries, LDAP bind/discovery/membership mutation, Vault Transit and the full synthetic assurance flow. No real provider is contacted.

The primary E2E imports people, discovers SCIM and LDAP identities, correlates Alex Morgan, detects orphan and ambiguous identities, requires approval, disables accounts, reads providers again, writes snapshots/evidence and concludes `VERIFIED`. Negative cases prove provider unavailability and PATCH-success/state-still-active never become `VERIFIED`. Playwright exercises the browser flow and PDF evidence report.

`compose.load.yml` builds two independent API replicas behind Nginx and a dedicated PostgreSQL. `test/load` logs in once, runs 100 virtual users × 100 authenticated dashboard reads and fails when error rate exceeds 1% or p95 exceeds 750 ms. This 10,000-request horizontal gate is repeatable locally and in `.github/workflows/load.yml`; record the result for each release. It is a regression/capacity gate, not a replacement for environment-specific soak, failover and maximum-data-volume testing.

Local production-profile baseline on 2026-08-23: 10,000 requests, 100 virtual users, zero failures, p95 360.1 ms, 468.5 requests/second. Host/container capacity affects absolute numbers; the committed SLO remains the automated pass/fail criterion.

```text
go test ./backend/...
docker compose -f compose.test.yml up -d --build --wait
go test -tags=integration -count=1 ./backend/...
docker compose -f compose.test.yml down -v --remove-orphans
scripts/load.ps1
```

CI additionally runs formatting, vet, race tests, coverage generation, frontend lint/typecheck/Vitest/build, container builds and Playwright. Cleanup steps use `if: always()`.
