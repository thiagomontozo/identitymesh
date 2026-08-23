CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id),
  email text NOT NULL, display_name text NOT NULL, password_hash text NOT NULL, mfa_secret_ciphertext text,
  mfa_enabled boolean NOT NULL DEFAULT false, disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, email)
);
-- v0.1 login identifies a tenant user by email, so ambiguity across
-- organizations is rejected until organization-qualified login is introduced.
CREATE UNIQUE INDEX users_email_global_unique_idx ON users(lower(email));
CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash bytea NOT NULL UNIQUE,
  csrf_hash bytea NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE roles (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL UNIQUE);
CREATE TABLE permissions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL UNIQUE);
CREATE TABLE user_roles (organization_id uuid NOT NULL REFERENCES organizations(id), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id uuid NOT NULL REFERENCES roles(id), PRIMARY KEY (organization_id,user_id,role_id));

CREATE TABLE identity_connectors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), name text NOT NULL,
  type text NOT NULL CHECK (type IN ('CSV_AUTHORITATIVE_SOURCE','SCIM_2_0','LDAP_DIRECTORY')),
  base_url text, environment text NOT NULL DEFAULT 'PRODUCTION', credential_reference text,
  enabled boolean NOT NULL DEFAULT true, read_enabled boolean NOT NULL DEFAULT true, write_enabled boolean NOT NULL DEFAULT false,
  capabilities jsonb NOT NULL DEFAULT '[]', sync_interval text NOT NULL DEFAULT 'MANUAL', last_sync_at timestamptz,
  last_sync_status text NOT NULL DEFAULT 'UNKNOWN', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id,name)
);
CREATE TABLE connector_credentials (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), connector_id uuid NOT NULL REFERENCES identity_connectors(id) ON DELETE CASCADE, ciphertext text NOT NULL, key_version integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(connector_id));
CREATE TABLE people (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), authoritative_source_id uuid REFERENCES identity_connectors(id),
  external_person_id text NOT NULL, display_name text NOT NULL, primary_email text, username text, employee_number text, department text, team text,
  manager_person_id uuid REFERENCES people(id), lifecycle_status text NOT NULL CHECK (lifecycle_status IN ('PRE_HIRE','ACTIVE','LEAVE','SUSPENDED','TERMINATED','UNKNOWN')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, authoritative_source_id, external_person_id)
);
CREATE TABLE connector_syncs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), connector_id uuid NOT NULL REFERENCES identity_connectors(id),
  trigger_type text NOT NULL, status text NOT NULL, request_id text, started_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
  accounts_discovered integer NOT NULL DEFAULT 0, groups_discovered integer NOT NULL DEFAULT 0, error_code text, summary jsonb NOT NULL DEFAULT '{}'
);
CREATE TABLE identity_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), connector_id uuid NOT NULL REFERENCES identity_connectors(id),
  external_account_id text NOT NULL, username text NOT NULL, display_name text, primary_email text, employee_number text,
  active_status text NOT NULL DEFAULT 'UNKNOWN', account_type text NOT NULL DEFAULT 'UNKNOWN' CHECK (account_type IN ('HUMAN','SERVICE','GUEST','SHARED','UNKNOWN')),
  privileged boolean NOT NULL DEFAULT false, first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(),
  provider_created_at timestamptz, provider_updated_at timestamptz, last_activity_at timestamptz, raw_attributes_summary jsonb NOT NULL DEFAULT '{}',
  missing_since timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, connector_id, external_account_id)
);
CREATE TABLE identity_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), person_id uuid NOT NULL REFERENCES people(id),
  identity_account_id uuid NOT NULL REFERENCES identity_accounts(id), link_type text NOT NULL CHECK (link_type IN ('AUTOMATIC','MANUAL','AUTHORITATIVE')),
  confidence text NOT NULL CHECK (confidence IN ('HIGH','MEDIUM','LOW')), reason text NOT NULL, created_by uuid REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, identity_account_id)
);
CREATE TABLE correlation_candidates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), person_id uuid NOT NULL REFERENCES people(id),
  identity_account_id uuid NOT NULL REFERENCES identity_accounts(id), confidence text NOT NULL, reasons jsonb NOT NULL, status text NOT NULL DEFAULT 'PENDING',
  created_at timestamptz NOT NULL DEFAULT now(), reviewed_at timestamptz, reviewed_by uuid REFERENCES users(id), UNIQUE(organization_id,person_id,identity_account_id)
);
CREATE TABLE applications (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), name text NOT NULL, description text, owner_name text, owner_email text, criticality text NOT NULL DEFAULT 'MEDIUM', connector_id uuid REFERENCES identity_connectors(id), enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE entitlements (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), connector_id uuid NOT NULL REFERENCES identity_connectors(id), external_id text NOT NULL, name text NOT NULL, type text NOT NULL, description text, privileged boolean NOT NULL DEFAULT false, first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,connector_id,external_id));
CREATE TABLE access_grants (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), identity_account_id uuid NOT NULL REFERENCES identity_accounts(id), entitlement_id uuid NOT NULL REFERENCES entitlements(id), source text NOT NULL, first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(), active boolean NOT NULL DEFAULT true, UNIQUE(organization_id,identity_account_id,entitlement_id));

CREATE TABLE reconciliation_runs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), connector_id uuid NOT NULL REFERENCES identity_connectors(id), trigger_type text NOT NULL, status text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz, accounts_discovered integer NOT NULL DEFAULT 0, accounts_changed integer NOT NULL DEFAULT 0, groups_discovered integer NOT NULL DEFAULT 0, memberships_changed integer NOT NULL DEFAULT 0, findings_created integer NOT NULL DEFAULT 0, summary jsonb NOT NULL DEFAULT '{}');
CREATE TABLE identity_findings (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), person_id uuid REFERENCES people(id), identity_account_id uuid REFERENCES identity_accounts(id), connector_id uuid REFERENCES identity_connectors(id), type text NOT NULL, severity text NOT NULL CHECK (severity IN ('INFORMATIONAL','ATTENTION','WARNING','HIGH')), status text NOT NULL DEFAULT 'OPEN', reason text NOT NULL, first_observed_at timestamptz NOT NULL DEFAULT now(), last_observed_at timestamptz NOT NULL DEFAULT now(), resolved_at timestamptz);
CREATE TABLE lifecycle_cases (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), person_id uuid NOT NULL REFERENCES people(id), type text NOT NULL DEFAULT 'OFFBOARDING', requested_by uuid NOT NULL REFERENCES users(id), status text NOT NULL DEFAULT 'DRAFT', effective_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), approved_at timestamptz, started_at timestamptz, completed_at timestamptz, verification_status text, summary jsonb NOT NULL DEFAULT '{}');
CREATE TABLE lifecycle_actions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), case_id uuid NOT NULL REFERENCES lifecycle_cases(id), connector_id uuid REFERENCES identity_connectors(id), identity_account_id uuid REFERENCES identity_accounts(id), action_type text NOT NULL CHECK(action_type IN ('DISABLE_ACCOUNT','REMOVE_MEMBERSHIP','VERIFY_DISABLED','MANUAL_REVIEW')), status text NOT NULL DEFAULT 'PLANNED', desired_state jsonb NOT NULL DEFAULT '{}', idempotency_key text NOT NULL, approved_by uuid REFERENCES users(id), started_at timestamptz, completed_at timestamptz, attempt_count integer NOT NULL DEFAULT 0, error_code text, summary jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,idempotency_key));
CREATE TABLE action_attempts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), action_id uuid NOT NULL REFERENCES lifecycle_actions(id), attempt_number integer NOT NULL, request_id text, outcome text NOT NULL, provider_status integer, error_code text, started_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz, UNIQUE(action_id,attempt_number));
CREATE TABLE verification_snapshots (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), case_id uuid NOT NULL REFERENCES lifecycle_cases(id), observed_at timestamptz NOT NULL, connected_systems integer NOT NULL, systems_succeeded integer NOT NULL, systems_failed integer NOT NULL, managed_identities integer NOT NULL, disabled_identities integer NOT NULL, active_identities integer NOT NULL, unresolved_identities integer NOT NULL, status text NOT NULL, summary jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE lifecycle_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), case_id uuid NOT NULL REFERENCES lifecycle_cases(id), type text NOT NULL, summary text NOT NULL, metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE access_review_campaigns (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), name text NOT NULL, description text, scope_type text NOT NULL, scope_configuration jsonb NOT NULL DEFAULT '{}', reviewer_user_id uuid NOT NULL REFERENCES users(id), status text NOT NULL DEFAULT 'DRAFT', starts_at timestamptz, due_at timestamptz, completed_at timestamptz, created_by uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE access_review_items (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), campaign_id uuid NOT NULL REFERENCES access_review_campaigns(id), person_id uuid REFERENCES people(id), identity_account_id uuid REFERENCES identity_accounts(id), entitlement_id uuid REFERENCES entitlements(id), status text NOT NULL DEFAULT 'PENDING', observed_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE access_review_decisions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), item_id uuid NOT NULL REFERENCES access_review_items(id), reviewer_user_id uuid NOT NULL REFERENCES users(id), decision text NOT NULL CHECK(decision IN ('KEEP','REVOKE','NEEDS_INFORMATION','NOT_APPLICABLE')), comment text, proposed_action_id uuid REFERENCES lifecycle_actions(id), created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(item_id));
CREATE TABLE identity_evidence (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), connector_id uuid REFERENCES identity_connectors(id), person_id uuid REFERENCES people(id), identity_account_id uuid REFERENCES identity_accounts(id), lifecycle_case_id uuid REFERENCES lifecycle_cases(id), action_id uuid REFERENCES lifecycle_actions(id), type text NOT NULL, summary text NOT NULL, observed_state jsonb NOT NULL, source_timestamp timestamptz, created_at timestamptz NOT NULL DEFAULT now(), integrity_hash text);
CREATE TABLE audit_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), actor_user_id uuid REFERENCES users(id), event_type text NOT NULL, resource_type text NOT NULL, resource_id uuid, metadata jsonb NOT NULL DEFAULT '{}', request_id text NOT NULL, source_ip inet, timestamp timestamptz NOT NULL DEFAULT now());
CREATE TABLE notifications (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), type text NOT NULL, channel text NOT NULL, payload jsonb NOT NULL, status text NOT NULL DEFAULT 'PENDING', created_at timestamptz NOT NULL DEFAULT now(), delivered_at timestamptz);
CREATE TABLE scheduler_leases (name text PRIMARY KEY, owner_id text NOT NULL, acquired_at timestamptz NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE outbox_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), organization_id uuid NOT NULL REFERENCES organizations(id), type text NOT NULL, payload jsonb NOT NULL, attempts integer NOT NULL DEFAULT 0, available_at timestamptz NOT NULL DEFAULT now(), processed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());

CREATE INDEX people_org_status_idx ON people(organization_id,lifecycle_status);
CREATE INDEX people_org_email_idx ON people(organization_id,lower(primary_email));
CREATE INDEX accounts_org_connector_state_idx ON identity_accounts(organization_id,connector_id,active_status);
CREATE INDEX accounts_org_seen_idx ON identity_accounts(organization_id,last_seen_at);
CREATE INDEX findings_org_status_idx ON identity_findings(organization_id,status,last_observed_at DESC);
CREATE INDEX cases_org_status_idx ON lifecycle_cases(organization_id,status,created_at DESC);
CREATE INDEX evidence_org_case_idx ON identity_evidence(organization_id,lifecycle_case_id,created_at DESC);
CREATE INDEX audit_org_time_idx ON audit_events(organization_id,timestamp DESC);
CREATE INDEX outbox_available_idx ON outbox_events(available_at) WHERE processed_at IS NULL;

INSERT INTO roles(name) VALUES ('OWNER'),('IDENTITY_ADMIN'),('SECURITY_ADMIN'),('ACCESS_REVIEWER'),('OPERATOR'),('AUDITOR'),('VIEWER');
INSERT INTO permissions(name) VALUES ('person.read'),('person.manage'),('connector.read'),('connector.manage'),('connector.sync'),('identity.read'),('identity.link'),('identity.unlink'),('lifecycle.read'),('lifecycle.plan'),('lifecycle.approve'),('lifecycle.execute'),('access_review.read'),('access_review.manage'),('access_review.decide'),('evidence.read'),('audit.read'),('user.manage'),('settings.manage');

CREATE TABLE schema_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
INSERT INTO schema_migrations(version) VALUES ('001_initial');
