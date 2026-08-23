# CI/CD

CI runs on pushes to `main` and pull requests with minimum token permissions. It checks formatting/vet/unit tests, PostgreSQL/SCIM/OpenLDAP integrations, frontend lint/typecheck/tests/build, Docker images and cleanup. Critical E2E assertions are not skipped or weakened.

Release workflow is manual or tag-triggered. It validates and publishes backend/frontend images to GHCR with Buildx provenance and SBOM. It does not deploy to production infrastructure or create releases merely for testing.
