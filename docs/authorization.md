# Authorization

Roles are `OWNER`, `IDENTITY_ADMIN`, `SECURITY_ADMIN`, `ACCESS_REVIEWER`, `OPERATOR`, `AUDITOR`, and `VIEWER`. Permissions are fine-grained across people, connectors, identities, lifecycle, access reviews, evidence, audit, users and settings.

The backend checks permission for every protected operation. Frontend navigation or hidden buttons are convenience only. Organization is read from the authenticated session; request bodies and route resources cannot override it. Cross-tenant lookups return not found or forbidden without revealing existence.
