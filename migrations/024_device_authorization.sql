-- Durable device grants, shared by application instances. Secrets are stored only as hashes.
CREATE TABLE device_authorizations (
    device_hash VARCHAR(64) PRIMARY KEY,
    user_code VARCHAR(16) NOT NULL UNIQUE,
    cancel_hash VARCHAR(64) NOT NULL,
    application_id VARCHAR(36) NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    organization VARCHAR(100) NOT NULL,
    scope TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','cancelled','token_issued','completed')),
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + INTERVAL '10 minutes'),
    approved_at TIMESTAMPTZ,
    approval_token_hash VARCHAR(64),
    approval_expires_at TIMESTAMPTZ,
    last_poll_at TIMESTAMPTZ,
    poll_interval INTEGER NOT NULL DEFAULT 5 CHECK(poll_interval >= 5),
    token_id VARCHAR(36) REFERENCES tokens(id) ON DELETE CASCADE
);
CREATE INDEX device_authorizations_expiry ON device_authorizations(expires_at);
CREATE INDEX device_authorizations_application ON device_authorizations(application_id);

-- Signed session JWTs can exceed the original 512-character token column.
ALTER TABLE tokens ALTER COLUMN access_token TYPE TEXT;
ALTER TABLE tokens ALTER COLUMN refresh_token TYPE TEXT;
ALTER TABLE tokens ALTER COLUMN scope TYPE TEXT;
