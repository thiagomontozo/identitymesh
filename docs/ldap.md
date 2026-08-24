# LDAP and LDAPS

LDAP discovery performs authenticated subtree searches using administratively configured bind DN, search base and fixed user/group filters. It supports paged results, connection/request timeouts and LDAP or LDAPS. LDAPS requires TLS 1.2+ with normal certificate verification; insecure verification is never the default. Filters are configuration, not raw action input.

Writes remain disabled unless an administrator enables both `writeEnabled` and a matching capability and strategy:

- `PPOLICY_LOCK` updates the standard password-policy lock timestamp.
- `ACTIVE_DIRECTORY_UAC` sets the disabled bit while retaining other `userAccountControl` flags.
- membership removal is limited to `member`, `uniqueMember` or `memberUid` on a known discovered group.

No password change, arbitrary modify, delete, rename or browser-selected attribute is available. Disable and membership operations pre-read the object, act idempotently and read again before an offboarding can be verified. If no strategy is configured, planning produces verification/manual work rather than an unsafe write.

Integration tests run against isolated OpenLDAP with synthetic identities. They prove bind, discovery, groups, memberships, read-only refusal and real controlled membership removal; no corporate directory is contacted. Active Directory behavior is unit-tested at the typed strategy boundary and must also be accepted in the operator's own test forest before rollout.
