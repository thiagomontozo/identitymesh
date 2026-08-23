# Limitations

IdentityMesh v0.1 is experimental and is not production-ready, compliance-certified, zero-trust-certified, or a guarantee of complete identity visibility or offboarding.

Administrator email addresses are globally unique in v0.1 because login does not yet include an organization selector.

- Generic SCIM 2.0 is the primary writable connector; LDAP is read-only.
- No native Entra ID, Okta, Google Workspace, GitHub, Slack, AWS IAM, VPN or other provider-specific connector.
- Systems must be configured; there is no discovery of unknown systems.
- No destructive delete, bulk lifecycle, distributed queue/runner cluster or advanced approval graph.
- Process-local API rate limiting and bounded in-process workers; scheduler coordination uses PostgreSQL advisory locks, but there is no distributed queue/runner cluster.
- Local AES-GCM secrets only; no HSM or managed secret store implementation.
- PDF reports are lightweight single-page exports, not a certified evidence or legal-admissibility pipeline.
- No production-scale load testing or independent security certification.
