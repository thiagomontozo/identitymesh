# ADR 015: LDAP is read-only in v0.1

Status: Superseded by ADR 020

LDAP originally shipped read-only because mutation semantics vary by directory. ADR 020 adds only explicit, controlled and post-write-verified strategies; arbitrary mutation remains prohibited.
