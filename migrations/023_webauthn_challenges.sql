-- WebAuthn ceremony state must remain server-side and survive instance changes.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    request_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    owner VARCHAR(255) NOT NULL,
    purpose VARCHAR(32) NOT NULL CHECK (purpose IN ('registration', 'authentication')),
    origin TEXT NOT NULL,
    session_hash VARCHAR(64),
    state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (clock_timestamp() + INTERVAL '5 minutes')
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges(user_id, purpose);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at);
