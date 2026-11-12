BEGIN;
-- Secondary credentials can contain signing keys or structured header config;
-- custom OIDC URLs and sender/receiver configuration need lossless round trips.
ALTER TABLE providers ALTER COLUMN client_id2 TYPE TEXT;
ALTER TABLE providers ALTER COLUMN client_secret2 TYPE TEXT;
ALTER TABLE providers ALTER COLUMN custom_auth_url TYPE TEXT;
ALTER TABLE providers ALTER COLUMN custom_token_url TYPE TEXT;
ALTER TABLE providers ALTER COLUMN custom_user_info_url TYPE TEXT;
ALTER TABLE providers ALTER COLUMN custom_logo TYPE TEXT;
ALTER TABLE providers ALTER COLUMN receiver TYPE TEXT;
COMMIT;
