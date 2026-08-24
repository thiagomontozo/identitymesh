# 020 — Controlled LDAP writes

Status: Accepted

LDAP mutation is limited to explicit ppolicy lock, Active Directory UAC disable and whitelisted membership removal strategies. Write enablement requires matching capabilities/configuration and all actions re-read observed state. Arbitrary LDAP modifications, password operations and deletes are rejected because they undermine preview, capability and assurance guarantees.
