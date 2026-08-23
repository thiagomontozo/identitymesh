# Identity correlation

Correlation is deterministic and ordered. Exact immutable employee identifiers and authoritative external IDs are strongest. Exact unique email within an administratively trusted domain can auto-link with high confidence. Normalized usernames require additional consistent attributes and otherwise remain review candidates.

Display name equality never auto-links. A name-only match creates a low-confidence `PENDING` candidate with the explicit reason `name-only similarity is never auto-linked`. Accept and reject decisions are tenant-scoped transactions and should emit audit events. Links are unique per organization and account by default.

Correlation confidence is categorical (`HIGH`, `MEDIUM`, `LOW`) rather than a numeric score. Every outcome includes reasons that an operator can inspect.
