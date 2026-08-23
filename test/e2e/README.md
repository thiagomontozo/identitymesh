# Browser E2E

The executable Playwright specifications live in `frontend/e2e` so Node resolves
the frontend's pinned Playwright dependency without a second package tree. The
tests still exercise the isolated Docker environment described by
`compose.yml`; no real identity provider is contacted.
