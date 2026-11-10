-- Revoke every signed session for a user without changing password age metadata.
CREATE TABLE user_session_epochs (
    user_id VARCHAR(36) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    invalid_before TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
