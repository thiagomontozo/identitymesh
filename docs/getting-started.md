# Getting started

Prerequisites are Git, Docker Desktop with Linux containers, Go 1.24+ for host development, and Node 22+ for host frontend development. Docker-only builds do not require host Node.

Copy `.env.example` to `.env`, generate a random 32-byte master key encoded with base64, and provide independent high-entropy session and bootstrap secrets. Start `docker compose up --build`, wait for `/ready`, then open the frontend. Development permits HTTP only because it is explicitly marked as development; production connector origins default to HTTPS.

To run integrations, use `scripts/integration.ps1`. It creates labeled, synthetic PostgreSQL, SCIM and OpenLDAP resources and removes them in `finally`. Never point those environment variables at a real provider.
