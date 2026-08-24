# Getting started

Prerequisites are Git, Docker Desktop with Linux containers, Go 1.26.6+ for host development, and Node 22.19+ for host frontend development. Docker-only builds do not require host Node.

Copy `.env.example` to `.env`, generate a random 32-byte master key encoded with base64, and provide independent high-entropy session and bootstrap secrets. Start `docker compose up --build`, wait for `/ready`, then open the frontend. Development permits HTTP only because it is explicitly marked as development; production connector origins default to HTTPS. Production should select Vault Transit, distributed jobs and trusted ingress proxy CIDRs as documented in [deployment](deployment.md).

To run integrations, use `scripts/integration.ps1`. It creates labeled, synthetic PostgreSQL, SCIM, OpenLDAP and Vault resources and removes them in `finally`. Use `scripts/load.ps1` for horizontal validation. Never point test environment variables at a real provider.
