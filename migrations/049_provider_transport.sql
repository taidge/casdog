-- NULL and empty preserve the existing disable_ssl compatibility policy.
-- Explicit modes opt into upstream gomail SSL-selection semantics.
ALTER TABLE providers ADD COLUMN ssl_mode TEXT;
ALTER TABLE providers ADD CONSTRAINT providers_ssl_mode_valid
    CHECK (ssl_mode IS NULL OR ssl_mode IN ('', 'Auto', 'Enable', 'Disable'));
