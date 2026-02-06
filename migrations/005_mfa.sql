-- MFA table
CREATE TABLE IF NOT EXISTS user_mfa (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_type VARCHAR(50) NOT NULL,  -- totp, sms, email
    secret TEXT,
    recovery_codes TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, mfa_type)
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_user ON user_mfa(user_id);

-- Add MFA fields to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_mfa_type VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
