DO $purchase_benefits$
BEGIN
LOCK TABLE products, orders, subscriptions IN ACCESS EXCLUSIVE MODE;
ALTER TABLE products ADD COLUMN is_recharge BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE products ADD COLUMN recharge_options JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(recharge_options)='array');
ALTER TABLE products ADD COLUMN disable_custom_recharge BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE products ADD COLUMN plan_id VARCHAR(100) REFERENCES plans(id);

-- A purchase records identities and money before payment begins. Later product
-- or plan edits must never change the benefits of an already accepted checkout.
CREATE TABLE order_benefits (
    order_id VARCHAR(100) PRIMARY KEY REFERENCES orders(id) ON DELETE CASCADE,
    kind VARCHAR(20) NOT NULL CHECK (kind IN ('plan','recharge')),
    user_id VARCHAR(100) NOT NULL REFERENCES users(id),
    amount_cents BIGINT NOT NULL CHECK (amount_cents >= 0 AND amount_cents <= 900000000000000),
    plan_id VARCHAR(100) REFERENCES plans(id),
    pricing_id VARCHAR(100) REFERENCES pricings(id),
    period VARCHAR(20),
    role_id VARCHAR(100) REFERENCES roles(id),
    subscription_id VARCHAR(100),
    fulfilled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((kind='recharge' AND amount_cents>0 AND plan_id IS NULL AND pricing_id IS NULL AND period IS NULL AND role_id IS NULL)
        OR (kind='plan' AND plan_id IS NOT NULL AND pricing_id IS NOT NULL AND period IN ('monthly','yearly')))
);
-- Grants belong to the paid period, not to permanent user_roles membership.
-- Renewing before expiry adds a future period and preserves the old role until
-- that period ends. Authorization must query validity at request time.
CREATE TABLE subscription_grants (
    id VARCHAR(100) PRIMARY KEY,
    subscription_id VARCHAR(100) NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    order_id VARCHAR(100) NOT NULL UNIQUE REFERENCES orders(id),
    owner VARCHAR(100) NOT NULL,
    user_id VARCHAR(100) NOT NULL REFERENCES users(id),
    role_id VARCHAR(100) REFERENCES roles(id),
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL CHECK (ends_at>starts_at),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_subscription_grants_user_validity ON subscription_grants(user_id,starts_at,ends_at);

CREATE VIEW active_subscription_roles AS
SELECT DISTINCT u.id AS user_id,u.owner AS user_owner,u.name AS user_name,
    r.id AS role_id,r.owner AS role_owner,r.name AS role_name,
    r.owner || '/' || r.name AS qualified_role_name
FROM subscription_grants g
JOIN subscriptions s ON s.id=g.subscription_id AND s.owner=g.owner AND s.user_id=g.user_id
JOIN order_benefits b ON b.order_id=g.order_id AND b.kind='plan' AND b.user_id=g.user_id
    AND b.plan_id=s.plan_id AND b.pricing_id=s.pricing_id AND b.role_id=g.role_id AND b.fulfilled_at IS NOT NULL
JOIN users u ON u.id=g.user_id AND u.owner=g.owner AND u.is_deleted=false AND u.is_forbidden=false
JOIN plans p ON p.id=s.plan_id AND p.owner=g.owner AND p.is_deleted=false AND p.is_enabled=true
JOIN roles r ON r.id=g.role_id AND r.owner=g.owner AND r.is_deleted=false AND r.is_enabled=true
WHERE s.is_deleted=false AND lower(s.state)='active'
    AND s.start_date<=clock_timestamp() AND s.end_date>clock_timestamp()
    AND g.starts_at<=clock_timestamp() AND g.ends_at>clock_timestamp();

CREATE FUNCTION guard_purchase_benefit() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF OLD.fulfilled_at IS NOT NULL AND COALESCE(current_setting('casdog.checkout_write',true),'') <> 'on' THEN
            RAISE EXCEPTION 'A fulfilled purchase benefit is immutable' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP='INSERT' THEN
        IF NOT EXISTS(SELECT 1 FROM orders o JOIN users u ON u.id=NEW.user_id AND u.owner=o.owner WHERE o.id=NEW.order_id AND lower(o.state)='created' AND COALESCE(o.payment_id,'')='') THEN
            RAISE EXCEPTION 'Benefits must belong to the original buyer before checkout starts' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.order_id,NEW.kind,NEW.user_id,NEW.amount_cents,NEW.plan_id,NEW.pricing_id,NEW.period,NEW.role_id)
        IS DISTINCT FROM (OLD.order_id,OLD.kind,OLD.user_id,OLD.amount_cents,OLD.plan_id,OLD.pricing_id,OLD.period,OLD.role_id)
       OR COALESCE(current_setting('casdog.checkout_write',true),'') <> 'on'
       OR (OLD.fulfilled_at IS NOT NULL AND NEW.fulfilled_at IS DISTINCT FROM OLD.fulfilled_at) THEN
        RAISE EXCEPTION 'A purchase benefit snapshot is immutable' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_purchase_benefit BEFORE INSERT OR UPDATE OR DELETE ON order_benefits
    FOR EACH ROW EXECUTE FUNCTION guard_purchase_benefit();

CREATE FUNCTION guard_benefit_order() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF EXISTS(SELECT 1 FROM order_benefits WHERE order_id=OLD.id AND fulfilled_at IS NOT NULL) THEN
            RAISE EXCEPTION 'Keep the order history of a fulfilled purchase' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        RETURN OLD;
    END IF;
    IF EXISTS(SELECT 1 FROM order_benefits WHERE order_id=OLD.id) AND
       (NEW.owner,NEW."user",NEW.product_name,NEW.quantity,NEW.price,NEW.currency,NEW.plan_name,NEW.pricing_name)
       IS DISTINCT FROM (OLD.owner,OLD."user",OLD.product_name,OLD.quantity,OLD.price,OLD.currency,OLD.plan_name,OLD.pricing_name) THEN
        RAISE EXCEPTION 'A purchase order snapshot is immutable' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_benefit_order BEFORE UPDATE OR DELETE ON orders
    FOR EACH ROW EXECUTE FUNCTION guard_benefit_order();
END
$purchase_benefits$;
