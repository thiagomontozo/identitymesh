# 021 — Horizontal Kubernetes deployment

Status: Accepted

API replicas are stateless apart from PostgreSQL and Vault dependencies. Distributed jobs/rate limits, migration locks and idempotent bootstrap permit horizontal operation. The reference Kustomize profile uses rolling updates, PDB, HPA, probes, restricted security contexts and network policy; managed PostgreSQL/Vault remain external.
