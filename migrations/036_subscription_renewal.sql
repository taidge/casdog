DO $renewals$
BEGIN
LOCK TABLE subscriptions IN ACCESS EXCLUSIVE MODE;
-- Legacy auto_renew flags are deliberately not payment mandates. A real user
-- must opt in through the validated operational endpoint after this migration.
CREATE TABLE subscription_renewal_authorizations (
    subscription_id VARCHAR(100) PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    owner VARCHAR(100) NOT NULL,
    user_id VARCHAR(100) NOT NULL REFERENCES users(id),
    product_id VARCHAR(100) NOT NULL REFERENCES products(id),
    provider_id VARCHAR(100) NOT NULL REFERENCES providers(id),
    provider_fingerprint VARCHAR(64) NOT NULL,
    plan_id VARCHAR(100) NOT NULL REFERENCES plans(id),
    pricing_id VARCHAR(100) NOT NULL REFERENCES pricings(id),
    role_id VARCHAR(100) REFERENCES roles(id),
    period VARCHAR(20) NOT NULL CHECK(period IN ('monthly','yearly')),
    currency VARCHAR(10) NOT NULL,
    max_amount_cents BIGINT NOT NULL CHECK(max_amount_cents>=0 AND max_amount_cents<=900000000000000),
    mode VARCHAR(30) NOT NULL CHECK(mode IN ('balance','checkout_required')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    authorized_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE subscription_renewal_work (
    id VARCHAR(100) PRIMARY KEY,
    subscription_id VARCHAR(100) NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    due_at TIMESTAMPTZ NOT NULL,
    order_id VARCHAR(100) UNIQUE REFERENCES orders(id),
    state VARCHAR(30) NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','processing','retry','action_required','paid','blocked','canceled','superseded','failed')),
    lease_token VARCHAR(100),
    lease_until TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(subscription_id,due_at)
);
CREATE INDEX idx_subscription_renewal_work_due ON subscription_renewal_work(next_attempt_at,lease_until);
CREATE TABLE payment_reconcile_queue (
    payment_id VARCHAR(100) PRIMARY KEY REFERENCES payments(id) ON DELETE CASCADE,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_token VARCHAR(100),
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_payment_reconcile_queue_due ON payment_reconcile_queue(next_attempt_at,lease_until);
-- Legacy CRUD is not an alternative wallet mandate endpoint. Turning a flag
-- off remains allowed everywhere; turning it back on requires fresh validated
-- beneficiary consent, even when an old authorization row still exists.
CREATE FUNCTION guard_subscription_auto_renew() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.auto_renew AND NOT OLD.auto_renew AND COALESCE(current_setting('casdog.renewal_consent',true),'')<>'on' THEN
        RAISE EXCEPTION 'Enable renewal through the beneficiary consent endpoint' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_subscription_auto_renew BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE FUNCTION guard_subscription_auto_renew();
END
$renewals$;
