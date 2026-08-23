# Deployment

IdentityMesh v0.1 is experimental. A deployment needs PostgreSQL backups, HTTPS termination, secure cookies, protected session/master keys, least-privilege connector credentials, explicit allowed origins, network egress policy, monitoring, log redaction, MFA policy and tested rollback.

Run one control-plane process unless advisory-lock and worker behavior have been independently tested for the chosen topology. External connectors are not part of global readiness: one offline SCIM system should degrade its run, not terminate the platform.
