# 019 — Vault Transit and HSM boundary

Status: Accepted

Production deployments may delegate connector credential encryption/decryption to Vault Transit. Only opaque Vault ciphertext is persisted. HSM integration belongs behind Vault Enterprise seal wrap, so IdentityMesh never handles a hardware wrapping key or embeds PKCS#11. Vault availability, policy, rotation and HSM certification remain operational responsibilities.
