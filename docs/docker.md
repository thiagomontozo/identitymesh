# Docker

Backend and frontend images are multi-stage and run as non-root. IdentityMesh does not use privileged containers, host networking, host filesystem mounts, the Docker socket or arbitrary command execution.

The development compose file contains PostgreSQL, backend and frontend. The test compose project contains labeled temporary PostgreSQL, two synthetic SCIM providers and synthetic OpenLDAP. `docker compose -f compose.test.yml down -v --remove-orphans` removes only its project resources.
