# Database

PostgreSQL is the primary store. IDs are UUIDs and timestamps are `timestamptz` written in UTC. Every corporate record carries `organization_id`; compound uniqueness and query indexes preserve connector/account, source/person and action idempotency invariants.

SQL migrations are versioned and append-only after publication. Production operators should apply them in a controlled deployment step and back up before change. Provider calls are never held inside database transactions. Transactions protect correlation review, planning, approval, lifecycle state, verification, access-review decisions and associated durable events.

Migration 003 adds native connector types, leased `distributed_jobs`, shared `rate_limit_windows` and credential-provider metadata. Claims use row locks with `SKIP LOCKED`; expired leases are reclaimable and organization/idempotency uniqueness prevents duplicate enqueue. Rate-limit keys are SHA-256 hashes rather than durable raw IP/session identifiers. Migration and bootstrap paths use PostgreSQL advisory locks so concurrent replica starts remain safe.
