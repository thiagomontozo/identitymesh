# Troubleshooting

Use the API `requestId` to correlate an error with structured logs and audit. `/health` confirms the process; `/ready` confirms PostgreSQL and migrations. Connector health is investigated separately through the connector sync timeline.

If SCIM fails, check fixed base URL, TLS, service credential, pagination response, response-size limits, rate limiting and provider schema. If LDAP fails, check bind DN, search base/filter, TLS name and network reachability. Never disable TLS verification as a shortcut.

After interrupted tests, run `scripts/cleanup.ps1` and verify `docker ps -a --filter label=com.identitymesh.managed=true` is empty.
