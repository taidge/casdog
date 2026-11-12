-- Passwordless first-factor proofs are separate from recovery, signup and MFA
-- verification records. Browser proof secrets and delivered codes are hashed.
CREATE TABLE primary_auth_challenges (
    secret_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization VARCHAR(100) NOT NULL,
    application_id VARCHAR(36) NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    credential_stamp VARCHAR(64) NOT NULL,
    login_identifier TEXT NOT NULL,
    method VARCHAR(10) NOT NULL CHECK(method IN ('email','sms')),
    receiver TEXT NOT NULL,
    code_hash VARCHAR(64),
    context JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp()+INTERVAL '5 minutes')
);
CREATE INDEX primary_auth_challenges_user_idx ON primary_auth_challenges(user_id,created_at);
CREATE INDEX primary_auth_challenges_expiry_idx ON primary_auth_challenges(expires_at);
