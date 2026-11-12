-- Align the persisted Syncer contract with its public model and upstream names.
-- RENAME preserves configured external credentials and table mappings.
ALTER TABLE syncers RENAME COLUMN user_name TO "user";
ALTER TABLE syncers RENAME COLUMN database_name TO "database";
ALTER TABLE syncers RENAME COLUMN table_name TO "table";

-- Scheduling authority is server-only: generic Syncer CRUD cannot write leases.
CREATE TABLE syncer_runtime_state (
    syncer_id VARCHAR(36) PRIMARY KEY REFERENCES syncers(id) ON DELETE CASCADE,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token VARCHAR(36),
    lease_until TIMESTAMPTZ,
    last_started_at TIMESTAMPTZ,
    last_finished_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_failures>=0),
    last_error TEXT,
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);
INSERT INTO syncer_runtime_state(syncer_id) SELECT id FROM syncers;
CREATE INDEX syncer_runtime_due ON syncer_runtime_state(next_run_at,lease_until);

CREATE TABLE syncer_user_links (
    syncer_id VARCHAR(36) NOT NULL REFERENCES syncers(id) ON DELETE CASCADE,
    source_key TEXT NOT NULL,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(syncer_id,source_key),
    UNIQUE(syncer_id,user_id)
);
