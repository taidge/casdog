-- Password-proven second factors, shared by every application instance.
-- The HttpOnly browser secret and delivered OTP are never persisted in plaintext.
CREATE TABLE password_mfa_challenges (
    secret_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization VARCHAR(100) NOT NULL,
    application_id VARCHAR(36) REFERENCES applications(id) ON DELETE CASCADE,
    credential_stamp VARCHAR(64) NOT NULL,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
    code_hash VARCHAR(64),
    code_method VARCHAR(10),
    receiver TEXT,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + INTERVAL '5 minutes')
);
CREATE INDEX password_mfa_challenges_user_idx ON password_mfa_challenges(user_id, created_at);
CREATE INDEX password_mfa_challenges_expiry_idx ON password_mfa_challenges(expires_at);
