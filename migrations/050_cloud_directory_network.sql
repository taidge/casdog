-- Public cloud transport options may contain several endpoint URLs.
ALTER TABLE syncers ALTER COLUMN "database" TYPE TEXT;

CREATE TABLE syncer_network_approvals (
    syncer_id VARCHAR(36) PRIMARY KEY REFERENCES syncers(id) ON DELETE CASCADE,
    configuration_stamp VARCHAR(64) NOT NULL,
    generation VARCHAR(36) NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
