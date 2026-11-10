-- Recovery proofs are separate from generic verification codes and never stored in plaintext.
CREATE TABLE IF NOT EXISTS password_reset_requests (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    email_hash VARCHAR(64) NOT NULL,
    source_hash VARCHAR(64) NOT NULL,
    application_id VARCHAR(36),
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_password_reset_receiver ON password_reset_requests(owner, email_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_source ON password_reset_requests(source_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_requests(user_id);
