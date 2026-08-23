# ADR 008: Post-action reconciliation is required

Status: Accepted

HTTP success means only that a provider accepted a request. IdentityMesh re-reads provider state before a verification snapshot can conclude that the desired state was observed.
