# Secrets

Connector credentials are encrypted with AES-256-GCM. `IDENTITYMESH_MASTER_KEY` is a base64-encoded 32-byte key supplied outside the repository. It must not be logged, committed or stored beside encrypted database backups.

The v0.1 `SecretStore` interface allows later HashiCorp Vault, AWS Secrets Manager, Azure Key Vault or GCP Secret Manager implementations. Key rotation/version migration and HSM-backed protection are not yet implemented. UI responses show only configured/redacted state.
