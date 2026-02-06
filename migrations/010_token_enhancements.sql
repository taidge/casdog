-- Migration 010: Token and session enhancements

-- Session enhancements: add expiry tracking and client IP
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_ip VARCHAR(100);

-- Index for efficient expired session lookups
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
-- Index for application-level session queries
CREATE INDEX IF NOT EXISTS idx_sessions_application ON sessions(application);
-- Index for token application-level queries
CREATE INDEX IF NOT EXISTS idx_tokens_application ON tokens(application);
-- Index for token user-level queries
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
