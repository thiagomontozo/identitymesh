# 017 — PostgreSQL distributed job queue

Status: Accepted

Synchronization and lifecycle execution use durable PostgreSQL jobs with organization-scoped idempotency, `SKIP LOCKED` claims, expiring leases, heartbeats and bounded retries. PostgreSQL matches the modular-monolith operating model and transactionally records intent without adding Kafka/Redis. A dedicated broker may be reconsidered only for demonstrated regional or throughput requirements.
