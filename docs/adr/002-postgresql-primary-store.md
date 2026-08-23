# ADR 002: PostgreSQL primary store

Status: Accepted

PostgreSQL stores tenant state, jobs, leases, evidence and audit. It provides transactions, constraints, JSON summaries and advisory locks without Kafka, Redis or a second operational database.
