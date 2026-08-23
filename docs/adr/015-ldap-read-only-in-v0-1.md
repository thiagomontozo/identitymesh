# ADR 015: LDAP is read-only in v0.1

Status: Accepted

LDAP discovery adds important internal-directory visibility, while safe cross-directory mutation semantics vary substantially. v0.1 discovers users, groups and memberships but exposes no write method.
