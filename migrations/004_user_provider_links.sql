-- User-to-provider links for social login
CREATE TABLE IF NOT EXISTS user_provider_links (
    id VARCHAR(255) PRIMARY KEY,
    owner VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_type VARCHAR(100) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    provider_username VARCHAR(255),
    provider_display_name VARCHAR(255),
    provider_email VARCHAR(255),
    provider_avatar_url TEXT,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, provider_type),
    UNIQUE(provider_type, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_user_provider_links_user ON user_provider_links(user_id);
CREATE INDEX IF NOT EXISTS idx_user_provider_links_provider ON user_provider_links(provider_type, provider_id);
