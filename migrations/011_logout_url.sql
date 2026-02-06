-- Add logout URL and redirect URI columns to applications for OIDC RP-initiated logout support
ALTER TABLE applications ADD COLUMN IF NOT EXISTS logout_url VARCHAR(500);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS logout_redirect_uris TEXT;
