# Docker

Backend and frontend images are multi-stage and run as non-root. IdentityMesh does not use privileged containers, host networking, host filesystem mounts, the Docker socket or arbitrary command execution.

The development compose file contains PostgreSQL, backend and frontend. The test project contains labeled temporary PostgreSQL, two synthetic SCIM providers, OpenLDAP and Vault. The load project contains PostgreSQL, two API replicas, Nginx and the compiled load driver. Their `down -v --remove-orphans` commands remove only project-owned resources.
