# Connectors

Connectors declare discovery and mutation capabilities. New connectors start read-only; an administrator must separately enable writes. The browser cannot supply arbitrary paths, HTTP methods, JSON operations, shell commands or per-action URLs.

Implemented types are `CSV_AUTHORITATIVE_SOURCE`, `SCIM_2_0`, and read-only `LDAP_DIRECTORY`. Future provider-specific types are architectural roadmap items, not advertised as functional integrations.

The administrative UI and API can create, validate, test and synchronize SCIM and LDAP connectors. LDAP configuration includes fixed bind DN, search base, user/group filters, paging and TLS server name; the password is encrypted separately and is never returned. CSV connectors support a mandatory preview, re-validation and explicit confirm/apply operation.

Connector failures are isolated to their runs. Previously observed accounts are retained and become stale; a failed or partial discovery never means an absent account was deleted.
