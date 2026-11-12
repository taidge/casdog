DO $order_buyers$
BEGIN
LOCK TABLE orders,users,payments,transactions,order_benefits IN ACCESS EXCLUSIVE MODE;
PERFORM set_config('casdog.checkout_write','on',true);
ALTER TABLE orders ADD COLUMN buyer_id VARCHAR(100) REFERENCES users(id);

-- A paid benefit or purchase ledger records a real UUID. Legacy payments often
-- stored usernames in user_id, so never treat that field as an unconditional UUID.
UPDATE orders o SET buyer_id=b.user_id FROM order_benefits b JOIN users u ON u.id=b.user_id
WHERE b.order_id=o.id AND u.owner=o.owner;
UPDATE orders o SET buyer_id=t.user_id FROM payments p JOIN transactions t
    ON t.owner=p.owner AND t.name='purchase_'||p.name AND t.category='purchase'
    JOIN users u ON u.id=t.user_id AND u.owner=t.owner
WHERE o.payment_id=p.id AND o.owner=p.owner AND o.buyer_id IS NULL;
UPDATE orders o SET buyer_id=u.id FROM payments p JOIN users u ON u.id=p.user_id AND u.owner=p.owner
WHERE o.payment_id=p.id AND o.owner=p.owner AND o.buyer_id IS NULL
    AND p.user_id IS DISTINCT FROM o."user"
    AND p.user_id IS DISTINCT FROM o.owner||'/'||o."user";
-- A current username (even on an older account) is no historical identity
-- evidence. Unresolved rows stay NULL and are visible only to administrators.
-- Only a single proven buyer may normalize a linked legacy payment. Leave
-- unlinked or contradictory historical payment identities for operator review.
UPDATE payments p SET user_id=proven.buyer_id
FROM (SELECT payment_id,owner,min(buyer_id) AS buyer_id FROM orders
    WHERE buyer_id IS NOT NULL AND COALESCE(payment_id,'')<>''
    GROUP BY payment_id,owner HAVING count(DISTINCT buyer_id)=1) proven
WHERE p.id=proven.payment_id AND p.owner=proven.owner;
CREATE INDEX idx_orders_buyer_created ON orders(buyer_id,created_at DESC);

CREATE FUNCTION pin_order_buyer() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    target users%ROWTYPE;
    reference_owner TEXT;
    reference_name TEXT;
BEGIN
    IF TG_OP='UPDATE' THEN
        IF NEW.buyer_id IS DISTINCT FROM OLD.buyer_id THEN
            RAISE EXCEPTION 'Order buyer identity is immutable' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';
        END IF;
        IF OLD.buyer_id IS NOT NULL THEN
            IF NEW.owner IS DISTINCT FROM OLD.owner OR
                (NEW."user" IS DISTINCT FROM OLD."user" AND NOT EXISTS(
                    SELECT 1 FROM users WHERE id=OLD.buyer_id AND owner=NEW.owner AND name=NEW."user")) THEN
                RAISE EXCEPTION 'An order cannot be reassigned to another buyer' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';
            END IF;
            RETURN NEW;
        END IF;
        -- An unresolved historical username must not become today's new account
        -- merely because an unrelated order field was updated after migration.
        IF COALESCE(OLD."user",'')<>'' OR COALESCE(OLD.payment_id,'')<>'' OR lower(OLD.state)<>'created' THEN
            IF NEW.owner IS DISTINCT FROM OLD.owner OR NEW."user" IS DISTINCT FROM OLD."user" THEN
                RAISE EXCEPTION 'Resolve the historical buyer before changing this order' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';
            END IF;
            RETURN NEW;
        END IF;
    END IF;
    NEW.buyer_id=NULL;
    IF COALESCE(NEW."user",'')='' THEN RETURN NEW; END IF;
    IF position('/' IN NEW."user")>0 THEN
        reference_owner=split_part(NEW."user",'/',1);
        reference_name=substring(NEW."user" FROM position('/' IN NEW."user")+1);
        IF reference_owner<>NEW.owner THEN
            RAISE EXCEPTION 'Order buyer belongs to another tenant' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';
        END IF;
        SELECT * INTO target FROM users WHERE owner=NEW.owner AND name=reference_name AND is_deleted=false;
    ELSE
        SELECT * INTO target FROM users WHERE id=NEW."user" OR (owner=NEW.owner AND name=NEW."user")
            ORDER BY (id=NEW."user") DESC LIMIT 1;
    END IF;
    IF NOT FOUND OR target.owner<>NEW.owner OR target.is_deleted THEN
        RAISE EXCEPTION 'A real buyer from the order tenant is required' USING ERRCODE='23514',CONSTRAINT='checkout_lifecycle';
    END IF;
    NEW.buyer_id=target.id;
    NEW."user"=target.name;
    RETURN NEW;
END $$;
CREATE TRIGGER pin_order_buyer BEFORE INSERT OR UPDATE ON orders
    FOR EACH ROW EXECUTE FUNCTION pin_order_buyer();
END
$order_buyers$;
