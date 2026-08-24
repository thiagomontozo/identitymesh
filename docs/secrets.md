# Secret stores

`SecretStore` has two production-capable implementations. `LOCAL_AES_GCM` encrypts connector credentials with AES-256-GCM using an externally supplied base64 32-byte master key. `VAULT_TRANSIT` sends plaintext only over a verified fixed HTTPS origin to Vault Transit and stores Vault's opaque versioned ciphertext in PostgreSQL.

Vault configuration uses `IDENTITYMESH_VAULT_ADDR`, token, optional namespace, transit mount and key. Redirects cannot change origin, responses and retries are bounded, readiness checks Vault health, and the token/key never appear in API responses or structured logs. Production operators should inject a short-lived Vault token through their workload identity/secret mechanism and apply a policy limited to encrypt/decrypt on the configured key.

IdentityMesh does not implement PKCS#11 itself. HSM protection is an operational Vault boundary: when Vault Enterprise seal wrap is configured with an HSM/KMS seal, the application never receives the wrapping key. Vault HA, unseal, replication, transit-key rotation, audit devices and hardware certification are operator responsibilities.

The real integration suite starts isolated Vault, creates a Transit key and verifies encrypt/decrypt, opaque storage, wrong-context/malformed ciphertext handling and health. The local key is useful for development or constrained deployments; managed production environments should prefer Vault Transit.
