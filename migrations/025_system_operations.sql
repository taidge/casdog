-- Durable operation outcomes contain no provider secrets or identity documents.
CREATE TABLE IF NOT EXISTS system_upgrade_history (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    version TEXT NOT NULL,
    status JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS identification_verifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    subject_sha256 TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS identification_verifications_user ON identification_verifications(user_id, verified_at DESC);

ALTER TABLE system_upgrade_history ADD COLUMN IF NOT EXISTS journal JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE OR REPLACE FUNCTION casdog_invalidate_identification() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id_card_type, NEW.id_card, NEW.real_name) IS DISTINCT FROM (OLD.id_card_type, OLD.id_card, OLD.real_name) THEN
        NEW.is_verified := FALSE;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS casdog_identification_subject_changed ON users;
CREATE TRIGGER casdog_identification_subject_changed BEFORE UPDATE OF id_card_type, id_card, real_name ON users
FOR EACH ROW EXECUTE FUNCTION casdog_invalidate_identification();
