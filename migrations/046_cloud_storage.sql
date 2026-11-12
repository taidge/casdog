-- Service-account JSON and private signed URLs exceed the old short credential
-- and URL columns. Provider bucket/prefix validation remains in the services.
BEGIN;
ALTER TABLE providers ALTER COLUMN client_secret TYPE TEXT;
ALTER TABLE providers ALTER COLUMN bucket TYPE TEXT;
ALTER TABLE providers ALTER COLUMN path_prefix TYPE TEXT;
ALTER TABLE resources ALTER COLUMN url TYPE TEXT;
COMMIT;
