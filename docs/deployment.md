# Production deployment

The `deploy/kubernetes` Kustomize base supplies a production-oriented control plane: three backend replicas, two frontend replicas, rolling updates with zero planned backend unavailability, PodDisruptionBudget, HPA, non-root/read-only security contexts, dropped capabilities, probes, resources, TLS ingress and default-deny NetworkPolicy. Replace all example hostnames, image tags and secret references before applying.

Required managed dependencies are PostgreSQL and, for the recommended secret profile, Vault Transit. Both require independent HA, encryption, backup/restore drills, monitoring and upgrade procedures. Run migrations from an application instance under the migration advisory lock; migrations are additive/versioned. Never share development credentials.

Minimum production settings include `IDENTITYMESH_ENV=production`, secure cookies, an exact HTTPS allowed origin, `IDENTITYMESH_JOB_MODE=DISTRIBUTED`, unique worker IDs, conservative action/sync concurrency, trusted ingress proxy CIDRs and `VAULT_TRANSIT`. Bootstrap credentials should be used only for initial controlled provisioning, then removed from workload configuration.

Before rollout, operators must test a non-production tenant, native provider permissions, LDAP strategy behavior, Vault outage/recovery, PostgreSQL failover, backup restoration, ingress/header behavior and environment-specific load. Observe queue depth, dead jobs, provider latency/error rates, connector freshness, audit persistence, DB pool saturation and verification outcomes. Roll back application images without rolling back an already-published migration.

External connector failure does not fail global readiness. PostgreSQL, current migrations and the configured external secret store do. This keeps a single SaaS outage isolated while preventing an instance that cannot safely read local state or credentials from receiving traffic.
