# Native SaaS connectors

## Microsoft Entra ID

The connector targets a fixed Microsoft Graph origin, follows same-origin `@odata.nextLink`, reads users/groups/members and disables an account with the typed `accountEnabled=false` update. It reads the user before and after mutation, making an already-disabled identity idempotently successful and a post-write active identity a failed verification. The access token must permit only the configured tenant operations.

## Okta

The connector uses the configured Okta organization origin and `SSWS` service token, follows validated `Link: rel=next` pagination and discovers users/groups/members. Offboarding uses Okta's reversible suspend lifecycle operation. Destructive deactivate/delete is not used. A user read before and after the operation determines the observed state.

## Google Workspace

The connector uses the Admin SDK Directory API, requires an administratively fixed customer identifier, follows page tokens, and discovers users/groups/members. Controlled disable sets `suspended=true`, followed by a user read. The supplied bearer token is expected to represent a least-privilege service integration established by the operator.

## GitHub

The connector is scoped to an administratively fixed organization. It discovers organization members and teams and uses Link pagination. Because GitHub has no generic account-disable operation for an external user, offboarding uses `REMOVE_MEMBERSHIP`; a subsequent membership lookup must show absence. It does not delete a GitHub account or accept arbitrary repository actions.

## Shared safeguards

All four connectors validate their base origin, expose a fixed capability matrix, bound requests/responses/retries, never retry an ambiguous mutation blindly and require explicit write enablement plus lifecycle approval. Token issuance and automatic token rotation are not embedded in the current release.
