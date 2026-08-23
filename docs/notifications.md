# Notifications

IdentityMesh persists in-app notifications for connector synchronization failures and non-verified offboarding outcomes. An optional webhook notifier can be configured only through deployment environment variables; event requests are JSON, bounded by a timeout, signed with `X-IdentityMesh-Signature: sha256=…`, and never follow redirects.

The webhook URL is fixed at startup, must use HTTPS outside development/test, cannot contain credentials/query/fragment, and is re-resolved before delivery so link-local metadata destinations are rejected. Provider credentials, session cookies, CSRF values and encryption keys are never included. Notification failure does not overwrite the underlying assurance result.
