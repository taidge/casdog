-- Casdog Initial Migration
-- Compatible with PostgreSQL and MySQL (use appropriate syntax for your database)

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    website_url VARCHAR(512),
    favicon VARCHAR(512),
    password_type VARCHAR(50) NOT NULL DEFAULT 'argon2',
    default_avatar VARCHAR(512),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_organizations_owner ON organizations(owner);
CREATE INDEX idx_organizations_name ON organizations(name);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    avatar VARCHAR(512),
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX idx_users_owner ON users(owner);
CREATE INDEX idx_users_name ON users(name);
CREATE INDEX idx_users_email ON users(email);

-- Applications table
CREATE TABLE IF NOT EXISTS applications (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    logo VARCHAR(512),
    homepage_url VARCHAR(512),
    description TEXT,
    organization VARCHAR(100) NOT NULL,
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret VARCHAR(64) NOT NULL,
    redirect_uris TEXT NOT NULL,
    token_format VARCHAR(20) NOT NULL DEFAULT 'JWT',
    expire_in_hours INT NOT NULL DEFAULT 24,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX idx_applications_owner ON applications(owner);
CREATE INDEX idx_applications_organization ON applications(organization);
CREATE INDEX idx_applications_client_id ON applications(client_id);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX idx_roles_owner ON roles(owner);
CREATE INDEX idx_roles_name ON roles(name);

-- User roles mapping table
CREATE TABLE IF NOT EXISTS user_roles (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    resource_type VARCHAR(100) NOT NULL,
    resources TEXT NOT NULL,
    actions TEXT NOT NULL,
    effect VARCHAR(20) NOT NULL DEFAULT 'allow',
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX idx_permissions_owner ON permissions(owner);
CREATE INDEX idx_permissions_name ON permissions(name);

-- Role permissions mapping table
CREATE TABLE IF NOT EXISTS role_permissions (
    id VARCHAR(36) PRIMARY KEY,
    role_id VARCHAR(36) NOT NULL,
    permission_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

-- Casbin rule table (for sqlx-adapter)
CREATE TABLE IF NOT EXISTS casbin_rule (
    id SERIAL PRIMARY KEY,
    ptype VARCHAR(100) NOT NULL,
    v0 VARCHAR(100) NOT NULL,
    v1 VARCHAR(100) NOT NULL,
    v2 VARCHAR(100) NOT NULL,
    v3 VARCHAR(100),
    v4 VARCHAR(100),
    v5 VARCHAR(100)
);

CREATE INDEX idx_casbin_rule_ptype ON casbin_rule(ptype);

-- Insert default organization
INSERT INTO organizations (id, owner, name, display_name, password_type)
VALUES ('org_default', 'admin', 'built-in', 'Built-in Organization', 'argon2')
ON CONFLICT (name) DO NOTHING;

-- Insert default admin user (password: admin)
-- The password hash is for 'admin' using argon2
INSERT INTO users (id, owner, name, password_hash, display_name, is_admin)
VALUES (
    'user_admin',
    'built-in',
    'admin',
    '$argon2id$v=19$m=19456,t=2,p=1$bG9jYWxzYWx0MTIzNDU2$7j4yvNfOlvMYsPTQqEf3fvBLqkJRsZ5g5NvAIKJGGdY',
    'Administrator',
    TRUE
)
ON CONFLICT (owner, name) DO NOTHING;

-- Insert default admin role
INSERT INTO roles (id, owner, name, display_name, description, is_enabled)
VALUES ('role_admin', 'built-in', 'admin', 'Administrator', 'Full system access', TRUE)
ON CONFLICT (owner, name) DO NOTHING;

-- Assign admin role to admin user
INSERT INTO user_roles (id, user_id, role_id)
VALUES ('ur_admin', 'user_admin', 'role_admin')
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Insert default casbin policy for admin
INSERT INTO casbin_rule (ptype, v0, v1, v2)
VALUES ('p', 'admin', '*', '*')
ON CONFLICT DO NOTHING;

INSERT INTO casbin_rule (ptype, v0, v1)
VALUES ('g', 'admin', 'admin')
ON CONFLICT DO NOTHING;
