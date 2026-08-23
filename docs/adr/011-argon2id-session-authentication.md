# ADR 011: Argon2id and opaque sessions

Status: Accepted

Administrative passwords use Argon2id and sessions use random opaque cookies with hashed server records. Browser-local JWT storage was rejected to reduce token exposure.
