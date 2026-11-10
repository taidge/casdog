-- sqlx-adapter reads every policy component as a non-null string, including
-- unused components of grouping rules. Repair preexisting databases too.
UPDATE casbin_rule SET v0 = COALESCE(v0, ''), v1 = COALESCE(v1, ''),
    v2 = COALESCE(v2, ''), v3 = COALESCE(v3, ''), v4 = COALESCE(v4, ''), v5 = COALESCE(v5, '');
ALTER TABLE casbin_rule
    ALTER COLUMN v0 SET DEFAULT '', ALTER COLUMN v0 SET NOT NULL,
    ALTER COLUMN v1 SET DEFAULT '', ALTER COLUMN v1 SET NOT NULL,
    ALTER COLUMN v2 SET DEFAULT '', ALTER COLUMN v2 SET NOT NULL,
    ALTER COLUMN v3 SET DEFAULT '', ALTER COLUMN v3 SET NOT NULL,
    ALTER COLUMN v4 SET DEFAULT '', ALTER COLUMN v4 SET NOT NULL,
    ALTER COLUMN v5 SET DEFAULT '', ALTER COLUMN v5 SET NOT NULL;

-- Rust models use DateTime<Utc>/Timestamptz. Earlier migrations used naive
-- timestamps with CURRENT_TIMESTAMP defaults. Interpret those wall-clock values
-- in the database session's timezone. When legacy data used a different zone,
-- SET TIME ZONE to that zone before applying this migration.
DO $$
DECLARE col RECORD;
BEGIN
    FOR col IN SELECT table_name, column_name FROM information_schema.columns
        WHERE table_schema = current_schema() AND data_type = 'timestamp without time zone'
          AND table_name IN ('organizations', 'users', 'applications', 'roles',
              'permissions', 'providers', 'resources', 'certificates', 'groups',
              'sessions', 'tokens', 'webhooks', 'syncers', 'verifications',
              'invitations', 'records', 'orders', 'tickets', 'forms')
    LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE %L',
            col.table_name, col.column_name, col.column_name, current_setting('TimeZone'));
    END LOOP;
END $$;
