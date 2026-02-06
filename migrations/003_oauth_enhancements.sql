-- Phase 1A: Add cert column to applications
ALTER TABLE applications ADD COLUMN IF NOT EXISTS cert VARCHAR(100);

-- Phase 1B: Add OAuth columns to tokens table
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS nonce VARCHAR(255);
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS redirect_uri TEXT;
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS code_challenge_method VARCHAR(10);
