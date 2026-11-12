ALTER TABLE organizations
    ADD COLUMN kerberos_realm VARCHAR(200),
    ADD COLUMN kerberos_kdc_host VARCHAR(200),
    ADD COLUMN kerberos_keytab TEXT,
    ADD COLUMN kerberos_service_name VARCHAR(200);

-- Acceptor state is shared by every process. Do not tie receipts to users or
-- organizations: deleting an account/configuration must not resurrect a ticket.
CREATE TABLE kerberos_replays (
    fingerprint VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX kerberos_replays_expiry ON kerberos_replays(expires_at);
