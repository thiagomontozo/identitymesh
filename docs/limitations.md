# Limitations

IdentityMesh is a production deployment candidate, not a compliance-certified product or a guarantee of complete identity visibility/offboarding. Verification covers only connected, observable and successfully reconciled systems.

- Administrator email addresses are globally unique because login has no organization selector.
- Systems must be configured; unknown systems cannot be automatically discovered.
- Native Entra, Okta, Google and GitHub tokens are supplied/rotated externally; the application does not issue OAuth/service-account tokens.
- LDAP mutations are restricted to explicit ppolicy/Active Directory disable and known membership attributes. There is no arbitrary modify API.
- Slack, AWS IAM Identity Center, VPN and other roadmap connectors are not native implementations.
- No destructive account deletion or bulk lifecycle operation.
- The distributed queue/rate limiter use PostgreSQL; there is no separate regional message broker or globally replicated limiter.
- Vault HSM protection depends on an operator-managed Vault Enterprise seal-wrap deployment; physical HSM behavior was not validated in this repository's synthetic suite.
- The 10,000-request two-replica gate does not constitute exhaustive soak, disaster-recovery, geographic-latency or maximum-cardinality validation.
- Reports and hashes are integrity metadata, not forensic certification or a legal-admissibility claim.
- No independent security, privacy, zero-trust or regulatory certification.
