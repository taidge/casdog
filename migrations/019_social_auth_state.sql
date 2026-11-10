-- Shared, short-lived OAuth proofs. Only SHA-256 digests of browser secrets are persisted.
CREATE TABLE social_oauth_flows (
    state_hash VARCHAR(64) PRIMARY KEY,
    browser_hash VARCHAR(64) NOT NULL,
    provider_id VARCHAR(36) NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    application_id VARCHAR(36) NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    organization VARCHAR(100) NOT NULL,
    redirect_uri TEXT NOT NULL,
    purpose VARCHAR(16) NOT NULL CHECK (purpose IN ('signin', 'link')),
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes')
);
CREATE INDEX social_oauth_flows_expiry_idx ON social_oauth_flows(expires_at);
CREATE INDEX social_oauth_flows_org_idx ON social_oauth_flows(organization);

CREATE TABLE social_oauth_completions (
    secret_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id VARCHAR(36) NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    application_id VARCHAR(36) NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    organization VARCHAR(100) NOT NULL,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes')
);
CREATE INDEX social_oauth_completions_expiry_idx ON social_oauth_completions(expires_at);
CREATE INDEX social_oauth_completions_org_idx ON social_oauth_completions(organization);
