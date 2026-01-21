-- Casdog Additional Tables Migration

-- Providers table (OAuth, SMS, Email, Storage providers)
CREATE TABLE IF NOT EXISTS providers (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    display_name VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL, -- OAuth, SAML, LDAP, SMS, Email, Storage, Payment, Captcha
    type VARCHAR(50) NOT NULL, -- GitHub, Google, etc.
    sub_type VARCHAR(50),
    method VARCHAR(50),
    client_id VARCHAR(255),
    client_secret VARCHAR(255),
    client_id2 VARCHAR(255),
    client_secret2 VARCHAR(255),
    cert TEXT,
    custom_auth_url VARCHAR(512),
    custom_token_url VARCHAR(512),
    custom_user_info_url VARCHAR(512),
    custom_logo VARCHAR(512),
    scopes TEXT,
    user_mapping TEXT,
    http_headers TEXT,
    host VARCHAR(255),
    port INT,
    disable_ssl BOOLEAN NOT NULL DEFAULT FALSE,
    title VARCHAR(255),
    content TEXT,
    receiver VARCHAR(255),
    region_id VARCHAR(100),
    sign_name VARCHAR(100),
    template_code VARCHAR(100),
    app_id VARCHAR(100),
    endpoint VARCHAR(512),
    intranet_endpoint VARCHAR(512),
    domain VARCHAR(255),
    bucket VARCHAR(100),
    path_prefix VARCHAR(255),
    metadata TEXT,
    idp VARCHAR(255),
    issuer_url VARCHAR(512),
    enable_sign_authn_request BOOLEAN NOT NULL DEFAULT FALSE,
    provider_url VARCHAR(512),
    UNIQUE(owner, name)
);

CREATE INDEX idx_providers_owner ON providers(owner);
CREATE INDEX idx_providers_category ON providers(category);

-- Tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    application VARCHAR(100) NOT NULL,
    organization VARCHAR(100) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    code VARCHAR(255),
    access_token VARCHAR(512) NOT NULL,
    refresh_token VARCHAR(512),
    access_token_hash VARCHAR(255),
    refresh_token_hash VARCHAR(255),
    expires_in BIGINT NOT NULL DEFAULT 86400,
    scope VARCHAR(255) NOT NULL DEFAULT 'openid profile',
    token_type VARCHAR(50) NOT NULL DEFAULT 'Bearer',
    code_challenge VARCHAR(255),
    code_is_used BOOLEAN NOT NULL DEFAULT FALSE,
    code_expire_in BIGINT
);

CREATE INDEX idx_tokens_owner ON tokens(owner);
CREATE INDEX idx_tokens_access_token ON tokens(access_token);
CREATE INDEX idx_tokens_refresh_token ON tokens(refresh_token);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);

-- Groups table
CREATE TABLE IF NOT EXISTS groups (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    display_name VARCHAR(255) NOT NULL,
    manager VARCHAR(100),
    contact_email VARCHAR(255),
    type VARCHAR(50),
    parent_id VARCHAR(36),
    is_top_group BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(owner, name)
);

CREATE INDEX idx_groups_owner ON groups(owner);
CREATE INDEX idx_groups_parent_id ON groups(parent_id);

-- User groups mapping table
CREATE TABLE IF NOT EXISTS user_groups (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    group_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_groups_user_id ON user_groups(user_id);
CREATE INDEX idx_user_groups_group_id ON user_groups(group_id);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    application VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(36) NOT NULL,
    session_id VARCHAR(255) NOT NULL
);

CREATE INDEX idx_sessions_owner ON sessions(owner);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_session_id ON sessions(session_id);

-- Certificates table
CREATE TABLE IF NOT EXISTS certificates (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    display_name VARCHAR(255) NOT NULL,
    scope VARCHAR(50) NOT NULL, -- JWT, SAML
    type VARCHAR(50) NOT NULL, -- x509
    crypto_algorithm VARCHAR(50) NOT NULL, -- RS256, ES256
    bit_size INT NOT NULL DEFAULT 2048,
    expire_in_years INT NOT NULL DEFAULT 10,
    certificate TEXT NOT NULL,
    private_key TEXT NOT NULL,
    UNIQUE(owner, name)
);

CREATE INDEX idx_certificates_owner ON certificates(owner);

-- Resources table
CREATE TABLE IF NOT EXISTS resources (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(100) NOT NULL,
    provider VARCHAR(100),
    application VARCHAR(100),
    tag VARCHAR(100),
    parent VARCHAR(100),
    file_name VARCHAR(255) NOT NULL,
    file_type VARCHAR(100) NOT NULL,
    file_format VARCHAR(50),
    file_size BIGINT NOT NULL DEFAULT 0,
    url VARCHAR(1024) NOT NULL,
    description TEXT
);

CREATE INDEX idx_resources_owner ON resources(owner);
CREATE INDEX idx_resources_user_id ON resources(user_id);

-- Webhooks table
CREATE TABLE IF NOT EXISTS webhooks (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    organization VARCHAR(100) NOT NULL,
    url VARCHAR(1024) NOT NULL,
    method VARCHAR(20) NOT NULL DEFAULT 'POST',
    content_type VARCHAR(100) NOT NULL DEFAULT 'application/json',
    headers TEXT, -- JSON array
    events TEXT, -- JSON array
    is_user_extended BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(owner, name)
);

CREATE INDEX idx_webhooks_owner ON webhooks(owner);
CREATE INDEX idx_webhooks_organization ON webhooks(organization);

-- Syncers table
CREATE TABLE IF NOT EXISTS syncers (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    organization VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- Database, LDAP, Keycloak
    database_type VARCHAR(50),
    ssl_mode VARCHAR(50),
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    user_name VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    database_name VARCHAR(100),
    table_name VARCHAR(100),
    table_columns TEXT, -- JSON
    affiliation_table VARCHAR(100),
    avatar_base_url VARCHAR(512),
    error_text TEXT,
    sync_interval INT NOT NULL DEFAULT 60,
    is_read_only BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(owner, name)
);

CREATE INDEX idx_syncers_owner ON syncers(owner);
CREATE INDEX idx_syncers_organization ON syncers(organization);

-- Verifications table
CREATE TABLE IF NOT EXISTS verifications (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    remote_addr VARCHAR(100),
    type VARCHAR(50) NOT NULL, -- email, phone
    user_id VARCHAR(100) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    receiver VARCHAR(255) NOT NULL,
    code VARCHAR(20) NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_verifications_owner ON verifications(owner);
CREATE INDEX idx_verifications_receiver ON verifications(receiver);
CREATE INDEX idx_verifications_code ON verifications(code);

-- Invitations table
CREATE TABLE IF NOT EXISTS invitations (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    display_name VARCHAR(255) NOT NULL,
    code VARCHAR(100) NOT NULL,
    is_regexp BOOLEAN NOT NULL DEFAULT FALSE,
    quota INT NOT NULL DEFAULT 1,
    used_count INT NOT NULL DEFAULT 0,
    application VARCHAR(100),
    username VARCHAR(100),
    email VARCHAR(255),
    phone VARCHAR(50),
    signup_group VARCHAR(100),
    default_code VARCHAR(100),
    state VARCHAR(50) NOT NULL DEFAULT 'Active',
    UNIQUE(owner, name)
);

CREATE INDEX idx_invitations_owner ON invitations(owner);
CREATE INDEX idx_invitations_code ON invitations(code);

-- Records table (audit log)
CREATE TABLE IF NOT EXISTS records (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    organization VARCHAR(100),
    client_ip VARCHAR(100),
    user_id VARCHAR(100),
    method VARCHAR(20) NOT NULL,
    request_uri VARCHAR(1024) NOT NULL,
    action VARCHAR(100) NOT NULL,
    object TEXT,
    is_triggered BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_records_owner ON records(owner);
CREATE INDEX idx_records_user_id ON records(user_id);
CREATE INDEX idx_records_action ON records(action);
CREATE INDEX idx_records_created_at ON records(created_at);
