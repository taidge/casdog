-- Operational parity: durable coupons, usage reservations, webhook history and settings.
CREATE TABLE IF NOT EXISTS coupons (
 id VARCHAR(100) PRIMARY KEY, owner VARCHAR(100) NOT NULL, name VARCHAR(100) NOT NULL,
 code VARCHAR(100) NOT NULL, data JSONB NOT NULL DEFAULT '{}'::jsonb,
 used_count BIGINT NOT NULL DEFAULT 0 CHECK (used_count >= 0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(owner,name), UNIQUE(owner,code)
);
CREATE TABLE IF NOT EXISTS coupon_usages (
 id VARCHAR(100) PRIMARY KEY, coupon_id VARCHAR(100) NOT NULL REFERENCES coupons(id),
 user_id VARCHAR(100) NOT NULL REFERENCES users(id), order_id VARCHAR(100) NOT NULL UNIQUE REFERENCES orders(id),
 amount DOUBLE PRECISION NOT NULL CHECK (amount >= 0), consumed BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_coupon_usages_coupon_user ON coupon_usages(coupon_id,user_id);
CREATE TABLE IF NOT EXISTS operation_settings (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton), data JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO operation_settings(singleton,data) VALUES(TRUE,'{"owner":"admin","name":"setting-built-in","dbMaxOpenConns":0,"dbMaxIdleConns":0,"dbConnMaxLifetime":0,"recordRetentionDays":0}') ON CONFLICT DO NOTHING;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS auto_renew BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS domain_expire_time TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS webhook_events (
 id VARCHAR(100) PRIMARY KEY, owner VARCHAR(100) NOT NULL, name VARCHAR(100) NOT NULL,
 organization VARCHAR(100) NOT NULL, webhook_id VARCHAR(100) NOT NULL,
 event VARCHAR(100) NOT NULL, payload JSONB NOT NULL,
 state VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK(state IN ('Pending','Retrying','Success','Failed')),
 attempts INTEGER NOT NULL DEFAULT 0, status_code INTEGER, response_body TEXT, error_text TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(owner,name)
);
CREATE INDEX IF NOT EXISTS idx_webhook_events_org_created ON webhook_events(organization,created_at DESC);
CREATE OR REPLACE FUNCTION settle_coupon_usage() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE reservation coupon_usages%ROWTYPE;
BEGIN
 IF lower(NEW.state)='paid' AND lower(OLD.state) <> 'paid' THEN
  SELECT * INTO reservation FROM coupon_usages WHERE order_id=NEW.id AND consumed=false FOR UPDATE;
  IF FOUND THEN
   PERFORM 1 FROM coupons WHERE id=reservation.coupon_id FOR UPDATE;
   UPDATE coupons SET used_count=used_count+1,updated_at=NOW() WHERE id=reservation.coupon_id;
   UPDATE coupon_usages SET consumed=true WHERE id=reservation.id;
  END IF;
 ELSIF lower(NEW.state) IN ('canceled','cancelled','failed','timeout') THEN
  DELETE FROM coupon_usages WHERE order_id=NEW.id AND consumed=false;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trigger_settle_coupon_usage ON orders;
CREATE TRIGGER trigger_settle_coupon_usage AFTER UPDATE OF state ON orders FOR EACH ROW EXECUTE FUNCTION settle_coupon_usage();

-- Redemption history must survive administrative order deletion attempts.
ALTER TABLE coupon_usages DROP CONSTRAINT IF EXISTS coupon_usages_order_id_fkey;
ALTER TABLE coupon_usages ADD CONSTRAINT coupon_usages_order_id_fkey FOREIGN KEY(order_id) REFERENCES orders(id);
