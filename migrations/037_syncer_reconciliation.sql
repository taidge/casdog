-- Three-way sync state belongs to the owning Syncer, never to all tenant users.
ALTER TABLE syncer_user_links
    ADD COLUMN baseline_local JSONB,
    ADD COLUMN baseline_source JSONB,
    ADD COLUMN baseline_config_hash TEXT,
    ADD COLUMN conflict_state TEXT,
    ADD COLUMN conflict_at TIMESTAMPTZ,
    ADD COLUMN last_seen_at TIMESTAMPTZ,
    ADD COLUMN disabled_by_sync BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN disabled_user_updated_at TIMESTAMPTZ;

-- Commit intent locally before any remote write. Logical IDs deliberately keep
-- operation evidence after a user/configuration is deleted; handlers fence and
-- cancel these operations using current tenant/configuration/lease state.
CREATE TABLE syncer_operations (
    id VARCHAR(36) PRIMARY KEY,
    syncer_id VARCHAR(36) NOT NULL,
    source_key TEXT NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    organization VARCHAR(100) NOT NULL,
    config_hash TEXT NOT NULL,
    expected_source JSONB,
    desired_source JSONB NOT NULL CHECK(jsonb_typeof(desired_source)='object'),
    local_snapshot JSONB NOT NULL CHECK(jsonb_typeof(local_snapshot)='object'),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','applied','conflict','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX syncer_pending_operation ON syncer_operations(syncer_id,source_key) WHERE status='pending';
CREATE INDEX syncer_operation_queue ON syncer_operations(syncer_id,status,created_at);

-- Normal user CRUD wakes every writable syncer for the affected tenant. A
-- generation fence prevents run completion from losing an edit made mid-run.
ALTER TABLE syncer_runtime_state
    ADD COLUMN change_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN claimed_generation BIGINT NOT NULL DEFAULT 0;
CREATE FUNCTION wake_writable_syncers() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND
       ROW(NEW.owner,NEW.name,NEW.display_name,NEW.first_name,NEW.last_name,NEW.email,NEW.email_verified,NEW.phone,NEW.avatar,NEW.affiliation,NEW.external_id,NEW.ldap,NEW.signup_application,NEW.password_hash,NEW.password_type,NEW.password_salt,NEW.is_forbidden,NEW.is_deleted,NEW.is_admin,NEW.score)
       IS NOT DISTINCT FROM
       ROW(OLD.owner,OLD.name,OLD.display_name,OLD.first_name,OLD.last_name,OLD.email,OLD.email_verified,OLD.phone,OLD.avatar,OLD.affiliation,OLD.external_id,OLD.ldap,OLD.signup_application,OLD.password_hash,OLD.password_type,OLD.password_salt,OLD.is_forbidden,OLD.is_deleted,OLD.is_admin,OLD.score)
    THEN RETURN NEW; END IF;
    UPDATE syncer_runtime_state r
       SET next_run_at=LEAST(r.next_run_at,clock_timestamp()),
           change_generation=r.change_generation+1
      FROM syncers s
     WHERE s.id=r.syncer_id AND s.is_enabled AND NOT s.is_read_only
       AND (s.organization=NEW.owner OR (TG_OP='UPDATE' AND s.organization=OLD.owner));
    RETURN NEW;
END $$;
CREATE TRIGGER users_wake_writable_syncers
    AFTER INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION wake_writable_syncers();
