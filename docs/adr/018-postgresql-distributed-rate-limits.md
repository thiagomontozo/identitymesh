# 018 — PostgreSQL distributed rate limits

Status: Accepted

Sensitive-route fixed-window counters are atomically coordinated in PostgreSQL and keyed by hashes of client/tenant identity. This is consistent across API replicas and fails closed when unavailable. It avoids a new Redis dependency; global multi-region limiting remains outside the current boundary.
