# Database

PostgreSQL is the primary store. IDs are UUIDs and timestamps are `timestamptz` written in UTC. Every corporate record carries `organization_id`; compound uniqueness and query indexes preserve connector/account, source/person and action idempotency invariants.

SQL migrations are versioned and append-only after publication. Production operators should apply them in a controlled deployment step and back up before change. Provider calls are never held inside database transactions. Transactions protect correlation review, planning, approval, lifecycle state, verification, access-review decisions and associated durable events.
