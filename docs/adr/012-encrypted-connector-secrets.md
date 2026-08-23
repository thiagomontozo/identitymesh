# ADR 012: Encrypted connector secrets

Status: Accepted

Service credentials use authenticated AES-256-GCM encryption with an external master key. The interface permits future managed secret stores without changing connector APIs.
