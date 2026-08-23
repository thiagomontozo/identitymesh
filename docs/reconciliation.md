# Reconciliation

Reconciliation compares expected person lifecycle and access intent with a complete, successful provider observation. Runs are `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, or `PARTIAL` and retain counts and summaries.

Only a successful complete sync may mark an expected account missing according to an explicit policy. Failure, timeout, malformed output, or partial pagination preserves prior identities and marks data stale. Findings include active accounts for terminated people, orphans, unresolved identities, duplicate active accounts, privilege observations, stale connectors and state mismatches.
