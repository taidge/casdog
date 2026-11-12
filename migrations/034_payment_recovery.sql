-- Persist the exact external request before sending it. A retry after a crash
-- must reuse its payload and idempotency key, not today's mutable catalogue or
-- user profile. Short leases coordinate independent server instances.
CREATE TABLE payment_remote_operations (
    payment_id VARCHAR(100) PRIMARY KEY REFERENCES payments(id) ON DELETE CASCADE,
    checkout_request JSONB,
    provider_fingerprint VARCHAR(64),
    create_retry_until TIMESTAMPTZ,
    lease_token VARCHAR(100),
    lease_kind VARCHAR(20) CHECK (lease_kind IN ('create','reconcile','cancel')),
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    capture_key VARCHAR(100) NOT NULL DEFAULT gen_random_uuid()::text,
    capture_retry_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_payment_remote_operations_lease ON payment_remote_operations(lease_until);
