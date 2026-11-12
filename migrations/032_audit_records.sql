-- Align the original table with the record API and preserve wall-clock history
-- using the database's configured time zone. Service identities can include
-- both an application owner and name, so the actor is no longer 100 bytes.
DO $audit_records$
BEGIN
    ALTER TABLE records RENAME COLUMN user_id TO "user";
    ALTER TABLE records ALTER COLUMN "user" TYPE TEXT;
    -- Migration 015 already normalized the standard schema's timestamps.
    -- Retain existing instants, including ambiguous daylight-saving hours.
    IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='records'::regclass
        AND attname='created_at' AND atttypid='timestamp'::regtype AND NOT attisdropped) THEN
        ALTER TABLE records ALTER COLUMN created_at TYPE TIMESTAMPTZ
            USING created_at AT TIME ZONE current_setting('TimeZone');
    END IF;
END
$audit_records$;
