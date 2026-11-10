-- Hashes of explicitly logged-out session JWTs; never persist the raw bearer token.
CREATE TABLE IF NOT EXISTS revoked_session_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_revoked_sessions_expiry ON revoked_session_tokens(expires_at);
