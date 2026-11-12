-- A TOTP time step is proof once per account and authenticator, across all
-- enrollment/login ceremonies and application instances. Store a fingerprint
-- of the decoded secret rather than another copy of the authenticator secret.
CREATE TABLE user_totp_steps (
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_hash VARCHAR(64) NOT NULL,
    last_step BIGINT NOT NULL CHECK (last_step >= 0),
    PRIMARY KEY (user_id, secret_hash)
);
