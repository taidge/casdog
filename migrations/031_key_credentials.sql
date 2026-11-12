-- Credential provenance is server-owned and deliberately absent from Application
-- request/response models. Missing historical provenance must never imply admin.
CREATE TABLE application_credential_origins (
    application_id VARCHAR(36) PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    origin TEXT NOT NULL CHECK (origin IN ('unverified','static','dynamic')),
    application_owner TEXT NOT NULL,
    organization TEXT NOT NULL,
    approved_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO application_credential_origins(application_id,origin,application_owner,organization)
SELECT id,
    CASE WHEN left(name,4)='dcr_' OR tags @> '["dcr"]'::jsonb OR tags @> '["cimd"]'::jsonb
         THEN 'dynamic' ELSE 'unverified' END,
    owner, organization
FROM applications;
CREATE INDEX users_access_key_lookup ON users(access_key) WHERE access_key IS NOT NULL AND access_key<>'';
