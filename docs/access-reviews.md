# Access reviews

Campaigns define an application or entitlement scope, reviewer, start, due date and status. Items show the person, identity, entitlement, privilege indicator and last observation. Decisions are `KEEP`, `REVOKE`, `NEEDS_INFORMATION`, or `NOT_APPLICABLE` and retain reviewer, timestamp and comment.

`REVOKE` never calls a connector directly. It writes a proposed revocation event/action that must pass lifecycle approval and execution policy, allowing final provider results to be connected back to review evidence.
