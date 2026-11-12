BEGIN;
ALTER TABLE pricings ADD COLUMN is_invite_only BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pricings ADD COLUMN users JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE FUNCTION pricing_users_valid(value JSONB) RETURNS BOOLEAN LANGUAGE SQL IMMUTABLE AS $$
 SELECT CASE WHEN value IS NULL OR jsonb_typeof(value)<>'array' THEN FALSE ELSE
 jsonb_array_length(value)<=1000 AND NOT EXISTS(
 SELECT 1 FROM jsonb_array_elements(value) item WHERE jsonb_typeof(item)<>'string'
 OR length(item#>>'{}') NOT BETWEEN 1 AND 100 OR (item#>>'{}') ~ '[[:cntrl:]]') END
$$;
ALTER TABLE pricings ADD CONSTRAINT pricing_users_valid CHECK(pricing_users_valid(users));
COMMIT;
