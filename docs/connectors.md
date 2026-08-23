# Connectors

Connectors declare discovery and mutation capabilities. New connectors start read-only; an administrator must separately enable writes. The browser cannot supply arbitrary paths, HTTP methods, JSON operations, shell commands or per-action URLs.

Implemented types are `CSV_AUTHORITATIVE_SOURCE`, `SCIM_2_0`, and read-only `LDAP_DIRECTORY`. Future provider-specific types are architectural roadmap items, not advertised as functional integrations.

Connector failures are isolated to their runs. Previously observed accounts are retained and become stale; a failed or partial discovery never means an absent account was deleted.
