# Frontend

The web application uses React, TypeScript, Vite, React Router, Tailwind CSS and TanStack Query. All primary navigation surfaces are functional: Identity Assurance Overview, People/Person 360, identities and correlation candidates, applications/access, connectors, reconciliation, lifecycle cases, reviews and decisions, findings, evidence, PDF reports, users, audit and settings. Person 360 includes Overview, Identities, Access, Lifecycle, Findings, Evidence and Timeline tabs.

Status indicators pair text, icons/shapes and color. Forms use labels, keyboard-visible focus, semantic controls and accessible table structure. The UI never displays full connector credentials, session cookies, CSRF secrets or master keys. It supports TOTP enrollment/login, password change and active-session revocation. Navigation is role-aware while authorization remains enforced server-side.
