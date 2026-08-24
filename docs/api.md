# API

The JSON API is rooted at `/api/v1`. Errors use `{ "error": { "code", "message", "requestId" } }` and never expose stack traces. List resources accept bounded `limit` and `offset`; common resources accept filters/search.

Principal groups are auth, people, connectors/syncs, identities/correlation candidates, applications/entitlements/grants, reconciliation/findings, lifecycle cases/actions/events, access reviews, evidence/reports, users, audit and settings. Mutations use cookie authentication plus `X-CSRF-Token`.

See `openapi.yaml` for the maintained contract. SSE endpoints stream lifecycle progress; reconnecting clients should reload the authoritative case before relying on streamed events. Offboarding reports are returned as `application/pdf` with an `X-Content-SHA256` header and a persisted report-artifact record.

Authentication, connector test, connector sync, CSV preview and lifecycle execution have bounded PostgreSQL-coordinated rate limits shared by all API replicas. Connector test performs only a typed read of the expected endpoint and never uses write capability. In production, sync and lifecycle execution return `202 Accepted` after a durable distributed job is committed.
