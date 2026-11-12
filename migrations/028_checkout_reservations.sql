-- One SQL statement makes DDL and historical inventory reservations atomic,
-- including when the migration is executed without an outer migration runner.
DO $checkout_migration$
DECLARE
    invalid_checkout TEXT;
BEGIN
-- Prevent an old application writer from changing the snapshot while stock is
-- validated and reserved. Deployment must stop old server instances before
-- allowing traffic after this migration; their checkout writes lack the guard.
LOCK TABLE orders, payments, products IN ACCESS EXCLUSIVE MODE;

-- Reserve inventory before a remote checkout is created. Keep the reservation
-- through process restarts; finalization and release run under the order lock.
CREATE TABLE order_stock_reservations (
    order_id VARCHAR(100) PRIMARY KEY REFERENCES orders(id) ON DELETE CASCADE,
    product_id VARCHAR(100) NOT NULL REFERENCES products(id),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    finite_stock BOOLEAN NOT NULL,
    state VARCHAR(20) NOT NULL DEFAULT 'reserved'
        CHECK (state IN ('reserved', 'consumed', 'released')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_order_stock_reservations_product ON order_stock_reservations(product_id);

-- A linked checkout must have a single order, otherwise one notification could
-- settle only one of several orders sharing the payment.
CREATE UNIQUE INDEX idx_orders_checkout_payment ON orders(payment_id)
    WHERE payment_id IS NOT NULL AND payment_id <> '' AND is_deleted = false;

-- Snapshot only historical product checkouts still awaiting payment. Missing
-- or deleted linked payments are included so they fail validation rather than
-- silently losing a reservation. Already terminal history stays untouched.
CREATE TEMP TABLE checkout_pending_backfill ON COMMIT DROP AS
SELECT o.id AS order_id, o.owner, o.name AS order_name, o.product_name,
       o.quantity, o.price, o.currency, pay.id AS payment_id,
       pay.owner AS payment_owner, pay.is_deleted AS payment_deleted,
       pay.amount AS payment_amount, pay.currency AS payment_currency,
       product.id AS product_id, product.quantity AS stock
FROM orders o
LEFT JOIN payments pay ON pay.id=o.payment_id
LEFT JOIN products product ON product.owner=o.owner AND product.name=o.product_name AND product.is_deleted=false
WHERE o.is_deleted=false
  AND lower(o.state) IN ('created','processing','pending')
  AND COALESCE(o.payment_id,'') <> '' AND COALESCE(o.product_name,'') <> ''
  AND (pay.id IS NULL OR pay.is_deleted=true OR lower(pay.state) IN ('created','processing','pending'));

SELECT format('Legacy checkout %s/%s has a missing, deleted or foreign-tenant payment',owner,order_name)
INTO invalid_checkout FROM checkout_pending_backfill
WHERE payment_id IS NULL OR payment_deleted OR payment_owner <> owner LIMIT 1;
IF invalid_checkout IS NOT NULL THEN
    RAISE EXCEPTION '%',invalid_checkout USING ERRCODE='23514', CONSTRAINT='checkout_migration';
END IF;
SELECT format('Legacy checkout %s/%s has invalid quantity or missing owned product %s',owner,order_name,product_name)
INTO invalid_checkout FROM checkout_pending_backfill
WHERE quantity <= 0 OR product_id IS NULL LIMIT 1;
IF invalid_checkout IS NOT NULL THEN
    RAISE EXCEPTION '%',invalid_checkout USING ERRCODE='23514', CONSTRAINT='checkout_migration';
END IF;
SELECT format('Legacy checkout %s/%s has invalid, sub-cent or mismatched payment amounts/currency',owner,order_name)
INTO invalid_checkout FROM checkout_pending_backfill
WHERE price < 0 OR price > 9000000000000
   OR abs(round((price*100)::numeric) - (price*100)::numeric) > 0.000001
   OR payment_amount < 0 OR payment_amount > 9000000000000
   OR abs(payment_amount-price) > 0.000001
   OR upper(COALESCE(NULLIF(currency,''),'USD')) <> upper(COALESCE(NULLIF(payment_currency,''),'USD'))
LIMIT 1;
IF invalid_checkout IS NOT NULL THEN
    RAISE EXCEPTION '%',invalid_checkout USING ERRCODE='23514', CONSTRAINT='checkout_migration';
END IF;
SELECT format('Legacy pending checkouts for product %s/%s need %s units but only %s are available; reconcile pending payments before retrying migration',owner,product_name,sum(quantity),stock)
INTO invalid_checkout FROM checkout_pending_backfill
GROUP BY owner,product_name,product_id,stock
HAVING stock >= 0 AND sum(quantity) > stock LIMIT 1;
IF invalid_checkout IS NOT NULL THEN
    RAISE EXCEPTION '%',invalid_checkout USING ERRCODE='23514', CONSTRAINT='checkout_migration';
END IF;

-- Validate every product before changing any inventory. Finite products are
-- reduced by aggregate demand; unlimited inventory and historical sold totals
-- are preserved. Reservations retain the original per-order quantities.
UPDATE products product SET quantity=product.quantity-demand.quantity::integer,updated_at=NOW()
FROM (SELECT product_id,sum(quantity) AS quantity FROM checkout_pending_backfill WHERE stock >= 0 GROUP BY product_id) demand
WHERE product.id=demand.product_id;
INSERT INTO order_stock_reservations(order_id,product_id,quantity,finite_stock)
SELECT order_id,product_id,quantity,stock >= 0 FROM checkout_pending_backfill;

-- The compatibility CRUD endpoints also issue SQL directly. Protect the same
-- checkout invariants there, not just in the REST service. PaymentFlow marks
-- only its own transaction; this setting never survives a pool checkout.
CREATE FUNCTION guard_checkout_order() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM order_stock_reservations WHERE order_id=OLD.id AND state='reserved') THEN
            RAISE EXCEPTION 'Cancel a pending checkout before deleting its order' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF COALESCE(NEW.payment_id,'') <> '' AND COALESCE(current_setting('casdog.checkout_write',true),'') <> 'on' THEN
            RAISE EXCEPTION 'Use checkout to attach an order payment' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        RETURN NEW;
    END IF;
    IF COALESCE(OLD.payment_id,'') <> '' THEN
        IF (NEW.owner,NEW."user",NEW.product_name,NEW.quantity,NEW.price,NEW.currency,NEW.provider,NEW.payment_id,NEW.plan_name,NEW.pricing_name)
            IS DISTINCT FROM
           (OLD.owner,OLD."user",OLD.product_name,OLD.quantity,OLD.price,OLD.currency,OLD.provider,OLD.payment_id,OLD.plan_name,OLD.pricing_name) THEN
            RAISE EXCEPTION 'A checkout order snapshot is immutable' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        IF lower(OLD.state) IN ('paid','failed','canceled','cancelled','timeout') AND lower(NEW.state) <> lower(OLD.state) THEN
            RAISE EXCEPTION 'A final checkout order state is immutable' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        IF NEW.state IS DISTINCT FROM OLD.state AND COALESCE(current_setting('casdog.checkout_write',true),'') <> 'on' THEN
            RAISE EXCEPTION 'Use a verified payment notification to settle checkout' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
    ELSIF COALESCE(NEW.payment_id,'') <> '' AND COALESCE(current_setting('casdog.checkout_write',true),'') <> 'on' THEN
        RAISE EXCEPTION 'Use checkout to attach an order payment' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
    END IF;
    IF NEW.is_deleted AND EXISTS (SELECT 1 FROM order_stock_reservations WHERE order_id=OLD.id AND state='reserved') THEN
        RAISE EXCEPTION 'Cancel a pending checkout before deleting its order' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_checkout_order BEFORE INSERT OR UPDATE OR DELETE ON orders
    FOR EACH ROW EXECUTE FUNCTION guard_checkout_order();

CREATE FUNCTION guard_checkout_payment() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM orders o JOIN order_stock_reservations r ON r.order_id=o.id WHERE o.payment_id=OLD.id AND r.state='reserved') THEN
            RAISE EXCEPTION 'Cancel a pending checkout before deleting its payment' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        RETURN OLD;
    END IF;
    IF EXISTS (SELECT 1 FROM orders WHERE payment_id=OLD.id AND is_deleted=false) THEN
        IF lower(OLD.state) IN ('paid','failed','canceled','cancelled','timeout') AND lower(NEW.state) <> lower(OLD.state) THEN
            RAISE EXCEPTION 'A final checkout payment state is immutable' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
        IF (NEW.owner,NEW.provider_id,NEW.payment_type,NEW.product_id,NEW.product_name,NEW.user_id,NEW.amount,NEW.currency,NEW.state,NEW.out_order_id,NEW.pay_url,NEW.is_deleted)
            IS DISTINCT FROM
           (OLD.owner,OLD.provider_id,OLD.payment_type,OLD.product_id,OLD.product_name,OLD.user_id,OLD.amount,OLD.currency,OLD.state,OLD.out_order_id,OLD.pay_url,OLD.is_deleted)
           AND COALESCE(current_setting('casdog.checkout_write',true),'') <> 'on' THEN
            RAISE EXCEPTION 'Use checkout or a payment notification to change checkout payment' USING ERRCODE='23514', CONSTRAINT='checkout_lifecycle';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_checkout_payment BEFORE UPDATE OR DELETE ON payments
    FOR EACH ROW EXECUTE FUNCTION guard_checkout_payment();

END
$checkout_migration$;
