# 016 — Native provider connectors

Status: Accepted

IdentityMesh implements typed Entra ID, Okta, Google Workspace and GitHub clients behind one normalized provider contract. Each preserves provider-specific disable/membership semantics, fixed endpoints, pagination and post-write reads. Generic arbitrary HTTP adapters were rejected because they would move high-impact method/path/body authority into configuration or the browser.
