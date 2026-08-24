ALTER TABLE identity_connectors DROP CONSTRAINT identity_connectors_type_check;
ALTER TABLE identity_connectors ADD CONSTRAINT identity_connectors_type_check CHECK (
  type IN (
    'CSV_AUTHORITATIVE_SOURCE',
    'SCIM_2_0',
    'LDAP_DIRECTORY',
    'ENTRA_ID',
    'OKTA',
    'GOOGLE_WORKSPACE',
    'GITHUB'
  )
);

CREATE TABLE distributed_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('CONNECTOR_SYNC','LIFECYCLE_EXECUTE')),
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','DEAD')),
  priority smallint NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000),
  idempotency_key text NOT NULL,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
  available_at timestamptz NOT NULL DEFAULT now(),
  lease_owner text,
  lease_until timestamptz,
  last_error_code text,
  last_error_summary text,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  UNIQUE (organization_id, idempotency_key)
);

CREATE INDEX distributed_jobs_claim_idx
  ON distributed_jobs(status, available_at, priority DESC, created_at)
  WHERE status IN ('QUEUED','RUNNING');
CREATE INDEX distributed_jobs_org_time_idx
  ON distributed_jobs(organization_id, created_at DESC);

CREATE TABLE rate_limit_windows (
  key_hash bytea NOT NULL,
  window_started_at timestamptz NOT NULL,
  request_count integer NOT NULL CHECK (request_count > 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (key_hash, window_started_at)
);
CREATE INDEX rate_limit_windows_expiry_idx ON rate_limit_windows(expires_at);

ALTER TABLE connector_credentials
  ADD COLUMN provider text NOT NULL DEFAULT 'LOCAL_AES_GCM'
  CHECK (provider IN ('LOCAL_AES_GCM','VAULT_TRANSIT'));

INSERT INTO schema_migrations(version) VALUES ('003_production_platform');
