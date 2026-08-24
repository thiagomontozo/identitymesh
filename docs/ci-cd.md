# CI/CD

CI runs on pushes to `main` and pull requests with minimum token permissions. It checks formatting/vet/race/unit tests, PostgreSQL/SCIM/OpenLDAP/Vault integrations, distributed worker/rate-limit coordination, frontend lint/typecheck/tests/build, Docker images, Playwright and cleanup. Critical E2E assertions are not skipped or weakened.

`Load Validation` runs on `main`, weekly and manually. It builds two backend replicas and fails the 10,000-request scenario if its error or latency SLO is exceeded. CodeQL analyzes Go and TypeScript/JavaScript independently.

Release workflow is manual or tag-triggered. It validates and publishes backend/frontend images to GHCR with Buildx provenance and SBOM. It does not deploy to production infrastructure or create releases merely for testing.
