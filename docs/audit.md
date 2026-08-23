# Audit

Audit events include organization, actor, event type, resource, metadata, request ID, optional source IP and UTC timestamp. Important events cover authentication, connector configuration and sync, imports, linking, offboarding stages, provider actions, evidence and review decisions.

Metadata must never contain bearer tokens, LDAP passwords, cookies, CSRF values, connector secrets or master keys. Request IDs propagate through API, logs, runs, actions and audit to support investigation.
