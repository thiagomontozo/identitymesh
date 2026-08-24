# Connectors

Every connector has a fixed administrative origin, explicit discovery/mutation capabilities and `writeEnabled=false` by default. The browser cannot choose arbitrary paths, methods, JSON bodies, LDAP attributes, scripts or per-action URLs. HTTP clients require HTTPS outside development/test, block link-local and metadata targets, reject cross-origin redirects, bound response size/time/retries and honor `Retry-After` for safe reads.

| Type | Discovery | Controlled offboarding write |
|---|---|---|
| CSV authoritative | People import after preview/confirm | None |
| SCIM 2.0 | Users, groups, membership, pagination | `active=false` PATCH, then GET |
| LDAP/LDAPS | Users, groups, membership, paging | ppolicy/AD disable or membership removal, then read |
| Microsoft Entra ID | Graph users, groups, members, pagination | `accountEnabled=false`, then GET |
| Okta | Users, groups, members, Link pagination | Suspend lifecycle action, then GET |
| Google Workspace | Directory users, groups, members, page tokens | `suspended=true`, then GET |
| GitHub | Organization members, teams, team members | Remove organization membership, then GET membership |

Provider access tokens are service credentials issued with the least privilege by the provider/operator and rotated outside IdentityMesh. Tokens are encrypted using the configured SecretStore and never returned by the API. Test Connection performs one bounded read and never exercises a write.

Sync failure retains prior observations as stale data. An incomplete/failed response never means an account disappeared. Native connectors share normalized `User`, `Group` and membership contracts so correlation, findings and verification apply consistently without pretending provider semantics are identical.

See [SCIM](scim.md), [LDAP](ldap.md) and [native providers](native-connectors.md).
