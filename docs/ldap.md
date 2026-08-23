# LDAP

LDAP is read-only in v0.1. The connector performs authenticated subtree searches for administratively configured user and group filters, handles paged results, applies timeouts and supports LDAP or LDAPS. LDAPS requires TLS 1.2+ and normal certificate verification; insecure verification is not enabled.

Filters are connector administration values, never raw browser input. The integration suite uses isolated OpenLDAP populated only with Alex Morgan, Jordan Lee and a synthetic backup service account. No corporate directory is contacted.

There is no enable, disable, membership mutation or password operation in the LDAP API. Offboarding produces `VERIFY_DISABLED` or `MANUAL_REVIEW` for these identities.
