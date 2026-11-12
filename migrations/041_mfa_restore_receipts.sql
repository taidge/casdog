-- Credential tombstones deliberately outlive user deletion and enrollment reset.
CREATE TABLE mfa_restore_hmac_key (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
 secret BYTEA NOT NULL CHECK(octet_length(secret)=32)
);
CREATE TABLE mfa_restore_receipts (
 organization VARCHAR(100) NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('totp','recovery')),
 fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64),
 restored_user_id TEXT NOT NULL,
 restored_by TEXT NOT NULL,
 restored_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization,kind,fingerprint)
);
