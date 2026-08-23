# Architecture

IdentityMesh is a modular monolith: one Go control plane owns HTTP, authentication, scheduling, connector execution and assurance workflows; React is a separate static web client; PostgreSQL is the authoritative local store. Modules communicate through typed Go APIs and durable database records rather than remote service boundaries.

```mermaid
flowchart TB
  Browser[React / TypeScript] -->|cookie session + CSRF| API[Go HTTP API]
  API --> Auth[Auth + RBAC]
  API --> People[People + Identity Graph]
  API --> Assurance[Correlation + Reconciliation + Lifecycle]
  API --> Reviews[Access Reviews + Evidence]
  Auth & People & Assurance & Reviews --> PG[(PostgreSQL)]
  Assurance --> Pool[Bounded Worker Pools]
  Pool --> Connectors[Typed Connector Layer]
  Connectors --> CSV[CSV]
  Connectors --> SCIM[SCIM 2.0]
  Connectors --> LDAP[LDAP read-only]
```

Remote operations never share an ACID transaction with PostgreSQL. IdentityMesh persists intent, commits, performs the provider operation, persists its outcome, reconciles observed state, and only then finalizes verification. Schedulers use PostgreSQL advisory locks so multiple instances do not run the same scheduled task concurrently.

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
  ORGANIZATION ||--o{ AUDIT_EVENT : records
```
