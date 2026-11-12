DO $cart$
BEGIN
LOCK TABLE orders,order_benefits,subscription_grants IN ACCESS EXCLUSIVE MODE;
CREATE TABLE carts(user_id VARCHAR(100) PRIMARY KEY REFERENCES users(id),owner VARCHAR(100) NOT NULL,revision BIGINT NOT NULL DEFAULT 0 CHECK(revision>=0),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE cart_items(id VARCHAR(100) PRIMARY KEY,user_id VARCHAR(100) NOT NULL REFERENCES carts(user_id) ON DELETE CASCADE,position INTEGER NOT NULL,product_id VARCHAR(100) NOT NULL REFERENCES products(id),quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 1000),pricing_id VARCHAR(100) REFERENCES pricings(id),plan_id VARCHAR(100) REFERENCES plans(id),period VARCHAR(20),custom_amount_cents BIGINT,currency VARCHAR(10) NOT NULL,UNIQUE(user_id,position));
CREATE TABLE order_lines(
 id VARCHAR(100) PRIMARY KEY,order_id VARCHAR(100) NOT NULL REFERENCES orders(id) ON DELETE CASCADE,position INTEGER NOT NULL,
 product_id VARCHAR(100) NOT NULL REFERENCES products(id),product_name VARCHAR(100) NOT NULL,display_name VARCHAR(255) NOT NULL,
 kind VARCHAR(20) NOT NULL CHECK(kind IN ('product','plan','recharge')),user_id VARCHAR(100) NOT NULL REFERENCES users(id),
 quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 1000),unit_amount_cents BIGINT NOT NULL CHECK(unit_amount_cents>=0 AND unit_amount_cents<=900000000000000),
 amount_cents BIGINT NOT NULL CHECK(amount_cents>=0 AND amount_cents<=900000000000000),currency VARCHAR(10) NOT NULL,
 plan_id VARCHAR(100) REFERENCES plans(id),pricing_id VARCHAR(100) REFERENCES pricings(id),plan_name VARCHAR(100),pricing_name VARCHAR(100),period VARCHAR(20),role_id VARCHAR(100) REFERENCES roles(id),
 subscription_id VARCHAR(100),fulfilled_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(order_id,position),
 CHECK(amount_cents<=unit_amount_cents*quantity),
 CHECK((kind='product' AND plan_id IS NULL AND pricing_id IS NULL AND role_id IS NULL AND period IS NULL) OR (kind='recharge' AND amount_cents>0 AND plan_id IS NULL AND pricing_id IS NULL AND role_id IS NULL AND period IS NULL) OR (kind='plan' AND plan_id IS NOT NULL AND pricing_id IS NOT NULL AND period IN ('monthly','yearly') AND quantity<=120))
);
CREATE TABLE cart_checkouts(user_id VARCHAR(100) NOT NULL REFERENCES users(id),revision BIGINT NOT NULL,order_id VARCHAR(100) NOT NULL REFERENCES orders(id),request_hash VARCHAR(64) NOT NULL,PRIMARY KEY(user_id,revision));
CREATE TABLE order_line_stock_reservations(line_id VARCHAR(100) PRIMARY KEY REFERENCES order_lines(id) ON DELETE CASCADE,order_id VARCHAR(100) NOT NULL REFERENCES orders(id),product_id VARCHAR(100) NOT NULL REFERENCES products(id),quantity INTEGER NOT NULL CHECK(quantity>0),finite_stock BOOLEAN NOT NULL,state VARCHAR(20) NOT NULL DEFAULT 'reserved' CHECK(state IN ('reserved','consumed','released')),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX idx_order_line_stock_parent ON order_line_stock_reservations(order_id);
ALTER TABLE subscription_grants ADD COLUMN order_line_id VARCHAR(100) REFERENCES order_lines(id);
ALTER TABLE subscription_grants DROP CONSTRAINT subscription_grants_order_id_key;
CREATE UNIQUE INDEX subscription_grants_legacy_order ON subscription_grants(order_id) WHERE order_line_id IS NULL;
CREATE UNIQUE INDEX subscription_grants_line ON subscription_grants(order_line_id) WHERE order_line_id IS NOT NULL;
-- Single-SKU history and multi-line purchases share one immutable provenance
-- interface. Legacy product identity comes from its durable stock reservation.
CREATE VIEW purchase_benefits AS
 SELECT b.order_id,NULL::VARCHAR(100) AS line_id,b.kind,b.user_id,b.amount_cents,b.plan_id,b.pricing_id,b.period,b.role_id,b.subscription_id,b.fulfilled_at,r.product_id,o.quantity
 FROM order_benefits b JOIN orders o ON o.id=b.order_id LEFT JOIN order_stock_reservations r ON r.order_id=b.order_id
 UNION ALL
 SELECT l.order_id,l.id AS line_id,l.kind,l.user_id,l.amount_cents,l.plan_id,l.pricing_id,l.period,l.role_id,l.subscription_id,l.fulfilled_at,l.product_id,l.quantity FROM order_lines l;
CREATE OR REPLACE VIEW active_subscription_roles AS
 SELECT DISTINCT u.id AS user_id,u.owner AS user_owner,u.name AS user_name,r.id AS role_id,r.owner AS role_owner,r.name AS role_name,r.owner||'/'||r.name AS qualified_role_name
 FROM subscription_grants g JOIN subscriptions s ON s.id=g.subscription_id AND s.owner=g.owner AND s.user_id=g.user_id
 JOIN purchase_benefits b ON b.order_id=g.order_id AND b.line_id IS NOT DISTINCT FROM g.order_line_id AND b.kind='plan' AND b.user_id=g.user_id AND b.plan_id=s.plan_id AND b.pricing_id=s.pricing_id AND b.role_id=g.role_id AND b.fulfilled_at IS NOT NULL
 JOIN users u ON u.id=g.user_id AND u.owner=g.owner AND NOT u.is_deleted AND NOT u.is_forbidden
 JOIN plans p ON p.id=s.plan_id AND p.owner=g.owner AND NOT p.is_deleted AND p.is_enabled
 JOIN roles r ON r.id=g.role_id AND r.owner=g.owner AND NOT r.is_deleted AND r.is_enabled
 WHERE NOT s.is_deleted AND lower(s.state)='active' AND s.start_date<=clock_timestamp() AND s.end_date>clock_timestamp() AND g.starts_at<=clock_timestamp() AND g.ends_at>clock_timestamp();
CREATE FUNCTION guard_order_line() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM orders o JOIN products p ON p.id=NEW.product_id AND p.owner=o.owner WHERE o.id=NEW.order_id AND o.buyer_id=NEW.user_id AND lower(o.state)='created' AND COALESCE(o.payment_id,'')='') THEN RAISE EXCEPTION 'Order lines require the original owned checkout before payment starts' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';END IF;RETURN NEW;
 END IF;
 IF COALESCE(current_setting('casdog.checkout_write',true),'')<>'on' THEN RAISE EXCEPTION 'Purchase lines are immutable; use payment checkout' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;
 IF (to_jsonb(NEW)-'fulfilled_at'-'subscription_id') IS DISTINCT FROM (to_jsonb(OLD)-'fulfilled_at'-'subscription_id') OR (OLD.fulfilled_at IS NOT NULL AND NEW.fulfilled_at IS DISTINCT FROM OLD.fulfilled_at) THEN RAISE EXCEPTION 'Purchase line snapshot is immutable' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_order_line BEFORE INSERT OR UPDATE OR DELETE ON order_lines FOR EACH ROW EXECUTE FUNCTION guard_order_line();
CREATE FUNCTION guard_cart_order() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM order_lines WHERE order_id=OLD.id) THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF TG_OP='DELETE' THEN IF COALESCE(current_setting('casdog.checkout_write',true),'')='on' THEN RETURN OLD;END IF;RAISE EXCEPTION 'Keep cart purchase history' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';END IF;
 IF (NEW.owner,NEW.buyer_id,NEW."user",NEW.product_name,NEW.quantity,NEW.price,NEW.currency,NEW.plan_name,NEW.pricing_name) IS DISTINCT FROM (OLD.owner,OLD.buyer_id,OLD."user",OLD.product_name,OLD.quantity,OLD.price,OLD.currency,OLD.plan_name,OLD.pricing_name) THEN RAISE EXCEPTION 'Cart order snapshot is immutable' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';END IF;
 IF (NEW.state IS DISTINCT FROM OLD.state OR NEW.provider IS DISTINCT FROM OLD.provider) AND COALESCE(current_setting('casdog.checkout_write',true),'')<>'on' THEN RAISE EXCEPTION 'Use checkout to change a cart order lifecycle' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';END IF;
 IF NEW.is_deleted AND EXISTS(SELECT 1 FROM order_line_stock_reservations WHERE order_id=OLD.id AND state='reserved') THEN RAISE EXCEPTION 'Cancel the remote checkout before deleting its cart order' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_cart_order BEFORE UPDATE OR DELETE ON orders FOR EACH ROW EXECUTE FUNCTION guard_cart_order();
END
$cart$;
