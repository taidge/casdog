-- Migration 012: add Casdoor-compatible rule and site resources

CREATE TABLE IF NOT EXISTS rules (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    rule_type VARCHAR(100) NOT NULL,
    expressions JSONB NOT NULL DEFAULT '[]'::jsonb,
    action VARCHAR(100) NOT NULL DEFAULT 'Block',
    status_code INT NOT NULL DEFAULT 403,
    reason VARCHAR(255) NOT NULL DEFAULT 'Request blocked by rule',
    is_verbose BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX IF NOT EXISTS idx_rules_owner ON rules(owner);
CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_rules_updated_at ON rules(updated_at);

CREATE TABLE IF NOT EXISTS sites (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),
    tag VARCHAR(100),
    domain VARCHAR(255) NOT NULL,
    other_domains JSONB,
    need_redirect BOOLEAN NOT NULL DEFAULT FALSE,
    disable_verbose BOOLEAN NOT NULL DEFAULT FALSE,
    rules JSONB,
    enable_alert BOOLEAN NOT NULL DEFAULT FALSE,
    alert_interval INT NOT NULL DEFAULT 60,
    alert_try_times INT NOT NULL DEFAULT 3,
    alert_providers JSONB,
    challenges JSONB,
    host VARCHAR(255),
    port INT NOT NULL DEFAULT 443,
    hosts JSONB,
    ssl_mode VARCHAR(100) NOT NULL DEFAULT 'HTTPS Only',
    ssl_cert VARCHAR(100),
    public_ip VARCHAR(100),
    node VARCHAR(100),
    status VARCHAR(100) NOT NULL DEFAULT 'Active',
    nodes JSONB,
    casdoor_application VARCHAR(100),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX IF NOT EXISTS idx_sites_owner ON sites(owner);
CREATE INDEX IF NOT EXISTS idx_sites_domain ON sites(domain);
CREATE INDEX IF NOT EXISTS idx_sites_tag ON sites(tag);
