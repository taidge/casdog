-- A private OAuth endpoint exception is an explicit global-administrator
-- decision, bound to the saved provider configuration, never to its owner name.
CREATE TABLE oauth_provider_network_approvals (
    provider_id TEXT PRIMARY KEY REFERENCES providers(id) ON DELETE CASCADE,
    configuration_stamp VARCHAR(64) NOT NULL,
    generation VARCHAR(36) NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
