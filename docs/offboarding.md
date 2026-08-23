# Offboarding

```mermaid
flowchart TB
  C[Create case] --> D[Discover linked identities] --> P[Generate preview]
  P --> A[Explicit approval] --> E[Execute controlled actions]
  E --> R[Reconcile provider] --> V[Verify observed state] --> EV[Create evidence]
```

A plan is centered on one person. Writable SCIM identities with declared capability receive `DISABLE_ACCOUNT`; already-disabled or read-only identities receive `VERIFY_DISABLED`; unsupported/manual systems receive `MANUAL_REVIEW`. v0.1 has no destructive delete and no mass-disable action.
