-- Casbin Models table (stores model configurations)
CREATE TABLE IF NOT EXISTS casbin_models (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    model_text TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);

-- Casbin Adapters table (stores adapter configurations)
CREATE TABLE IF NOT EXISTS casbin_adapters (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    adapter_type VARCHAR(50) NOT NULL DEFAULT 'database',
    host VARCHAR(500) DEFAULT '',
    database_type VARCHAR(50) DEFAULT 'postgresql',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);

-- Casbin Enforcers table (links model + adapter)
CREATE TABLE IF NOT EXISTS casbin_enforcers (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    model_id VARCHAR(100) REFERENCES casbin_models(id),
    adapter_id VARCHAR(100) REFERENCES casbin_adapters(id),
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);
