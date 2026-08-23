# SCIM 2.0

The generic connector implements paginated `GET /Users`, `GET /Users/{id}`, `GET /Groups`, `GET /Groups/{id}` and a typed PATCH operation that replaces `active` with `false`. It limits page size and response bytes, validates IDs, fixes requests to the configured origin, blocks cross-origin redirects and rejects link-local metadata endpoints.

Requests have connect and overall timeouts, at most three attempts, exponential backoff and bounded `Retry-After` handling for retryable responses. Mutation retry policy first favors observed state: an already-disabled identity is idempotent success. A successful PATCH does not verify offboarding; IdentityMesh reads the user again and evaluates `active`.

`test/mock-scim` is **TEST / DEMO ONLY**. It supports pagination, groups, disable, rate limiting, timeout, HTTP 500, malformed responses, stale metadata, PATCH failure and successful PATCH with inconsistent observed state.
