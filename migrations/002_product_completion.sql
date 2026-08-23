ALTER TABLE identity_connectors
  ADD COLUMN configuration jsonb NOT NULL DEFAULT '{}';

CREATE TABLE organization_settings (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  audit_retention_days integer NOT NULL DEFAULT 365 CHECK (audit_retention_days BETWEEN 30 AND 3650),
  evidence_retention_days integer NOT NULL DEFAULT 730 CHECK (evidence_retention_days BETWEEN 30 AND 3650),
  reconciliation_retention_days integer NOT NULL DEFAULT 180 CHECK (reconciliation_retention_days BETWEEN 7 AND 3650),
  report_retention_days integer NOT NULL DEFAULT 365 CHECK (report_retention_days BETWEEN 30 AND 3650),
  trusted_email_domains jsonb NOT NULL DEFAULT '[]',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identity_assurance_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  lifecycle_case_id uuid REFERENCES lifecycle_cases(id),
  type text NOT NULL CHECK (type IN ('OFFBOARDING_VERIFICATION','ORPHAN_IDENTITIES','ACCESS_REVIEW','CONNECTOR_RECONCILIATION')),
  status text NOT NULL DEFAULT 'GENERATED' CHECK (status IN ('GENERATED','EXPIRED','FAILED')),
  generated_by uuid REFERENCES users(id),
  content_hash text NOT NULL,
  generated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, lifecycle_case_id, type, content_hash)
);

CREATE INDEX connector_syncs_org_connector_time_idx ON connector_syncs(organization_id,connector_id,started_at DESC);
CREATE INDEX candidates_org_status_time_idx ON correlation_candidates(organization_id,status,created_at DESC);
CREATE INDEX grants_org_active_idx ON access_grants(organization_id,active,last_seen_at DESC);
CREATE INDEX reviews_org_status_due_idx ON access_review_campaigns(organization_id,status,due_at);
CREATE INDEX reports_org_time_idx ON identity_assurance_reports(organization_id,generated_at DESC);

INSERT INTO schema_migrations(version) VALUES ('002_product_completion');
