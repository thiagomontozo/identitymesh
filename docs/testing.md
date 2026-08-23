# Testing

Unit tests prioritize lifecycle transitions, honest verification outcomes, deterministic correlation, no name-only linking, RBAC, Argon2id, AES-GCM failures, CSV limits/formula safety, bounded workers and SCIM retry/pagination/write/read-after-write behavior.

Integration tests run against real PostgreSQL, the Go mock SCIM services and OpenLDAP. The primary E2E imports synthetic people, discovers SCIM and LDAP identities, correlates Alex Morgan, detects an orphan and an ambiguous candidate, generates an offboarding plan, blocks execution before approval, disables SCIM accounts, re-reads providers, verifies LDAP, writes a snapshot and evidence, and concludes `VERIFIED`.

Negative E2E tests require that an unavailable provider never returns `VERIFIED`, and that PATCH success followed by `active=true` concludes `FAILED`. Test fixtures contain no real identities or credentials.
