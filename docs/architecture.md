# Architecture

IdentityMesh is a horizontally deployable modular monolith. React is a static web client; interchangeable Go API replicas own authentication and domain APIs; PostgreSQL is the authoritative state, durable job queue, scheduler coordination and distributed rate-limit store. Vault Transit is the external production secret boundary.

```mermaid
flowchart TB
  Browser[React / TypeScript] --> LB[Ingress / load balancer]
  LB --> API1[Go API replica]
  LB --> API2[Go API replica]
  API1 & API2 --> Auth[Auth + RBAC + CSRF]
  API1 & API2 --> Domain[People + Correlation + Assurance]
  API1 & API2 --> Jobs[Leased distributed workers]
  Auth & Domain & Jobs --> PG[(PostgreSQL)]
  API1 & API2 --> Vault[Vault Transit]
  Jobs --> Connectors[Typed connectors]
  Connectors --> CSV[CSV]
  Connectors --> SCIM[SCIM]
  Connectors --> LDAP[LDAP / LDAPS]
  Connectors --> Native[Entra · Okta · Google · GitHub]
```

Workers claim jobs with `FOR UPDATE SKIP LOCKED`, record a lease owner/expiry, heartbeat while active, retry only within a bounded policy and move exhausted jobs to `DEAD`. Organization plus idempotency key prevents duplicate enqueue. Each replica also has conservative bounded pools, so horizontal scale cannot create unbounded provider calls.

The PostgreSQL fixed-window rate limiter atomically coordinates sensitive-route limits across replicas and hashes client/tenant keys before storage. Trusted proxy headers are honored only for configured proxy CIDRs. The limiter fails closed on its protected operations if PostgreSQL is unavailable.

Remote provider calls never run inside a long database transaction. IdentityMesh persists intent, commits, performs the typed provider call, records the result in a new transaction, reconciles observed state and only then finalizes verification.

```mermaid
erDiagram
  ORGANIZATION ||--o{ PERSON : owns
  ORGANIZATION ||--o{ IDENTITY_CONNECTOR : owns
  PERSON ||--o{ IDENTITY_LINK : has
  IDENTITY_ACCOUNT ||--o| IDENTITY_LINK : linked_by
  IDENTITY_CONNECTOR ||--o{ IDENTITY_ACCOUNT : discovers
  IDENTITY_ACCOUNT ||--o{ ACCESS_GRANT : receives
  ENTITLEMENT ||--o{ ACCESS_GRANT : grants
  PERSON ||--o{ LIFECYCLE_CASE : subject
  LIFECYCLE_CASE ||--o{ LIFECYCLE_ACTION : plans
  LIFECYCLE_CASE ||--o{ VERIFICATION_SNAPSHOT : verifies
  LIFECYCLE_CASE ||--o{ IDENTITY_EVIDENCE : supports
  ACCESS_REVIEW_CAMPAIGN ||--o{ ACCESS_REVIEW_ITEM : contains
  ORGANIZATION ||--o{ DISTRIBUTED_JOB : schedules
  ORGANIZATION ||--o{ AUDIT_EVENT : records
```
