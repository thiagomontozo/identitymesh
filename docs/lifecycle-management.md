# Lifecycle management

Lifecycle cases model onboarding, change and offboarding; the implemented workflow concentrates on offboarding. Valid transitions prevent jumping from draft or plan directly to execution. Mutating actions require a role with `lifecycle.approve`, then execution separately requires `lifecycle.execute`.

Every action has an organization-scoped idempotency key and attempt history. Bounded workers limit concurrent connector syncs and lifecycle actions. Provider calls occur after committed local state and before a new persistence transaction.
