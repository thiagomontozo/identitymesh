# ADR 001: Modular monolith

Status: Accepted

IdentityMesh uses one Go control plane with internal domain modules. This keeps lifecycle transactions and operations understandable in v0.1 without inventing network boundaries. Modules may be extracted only after measured scaling or isolation needs.
