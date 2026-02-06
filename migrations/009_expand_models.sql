-- Migration 009: Expand User, Organization, Application models to match Casdoor

-- =============================================
-- USERS table expansion
-- =============================================

-- Identity & Authentication
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS user_type VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_salt VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_type VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS hash VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS pre_hash VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS register_type VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS register_source VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_key VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_secret VARCHAR(100);

-- Profile Information
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_type VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS permanent_avatar VARCHAR(500);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS country_code VARCHAR(6);
ALTER TABLE users ADD COLUMN IF NOT EXISTS region VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS location VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS address JSONB;
ALTER TABLE users ADD COLUMN IF NOT EXISTS affiliation VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS title VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS homepage VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio VARCHAR(500);

-- Personal Details
ALTER TABLE users ADD COLUMN IF NOT EXISTS id_card_type VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS id_card VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS real_name VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS tag VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS language VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS gender VARCHAR(20);
ALTER TABLE users ADD COLUMN IF NOT EXISTS birthday VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS education VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_default_avatar BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_online BOOLEAN NOT NULL DEFAULT FALSE;

-- Gamification & Balance
ALTER TABLE users ADD COLUMN IF NOT EXISTS score INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS karma INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ranking INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS balance DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS balance_credit DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS currency VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS balance_currency VARCHAR(100);

-- Status
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_forbidden BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS signup_application VARCHAR(100);

-- Social Provider IDs (JSONB map instead of 78 individual columns)
ALTER TABLE users ADD COLUMN IF NOT EXISTS provider_ids JSONB;

-- Sign-in Tracking
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_ip VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_signin_time VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_signin_ip VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_signin_wrong_time VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS signin_wrong_times INT NOT NULL DEFAULT 0;

-- MFA (some may already exist from migration 005)
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_phone_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_email_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_codes JSONB;

-- Security
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_change_password_time VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS need_update_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ip_whitelist VARCHAR(200);

-- Properties & Custom
ALTER TABLE users ADD COLUMN IF NOT EXISTS properties JSONB;
ALTER TABLE users ADD COLUMN IF NOT EXISTS custom JSONB;

-- LDAP
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap VARCHAR(100);

-- Invitation
ALTER TABLE users ADD COLUMN IF NOT EXISTS invitation VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS invitation_code VARCHAR(100);

-- Groups
ALTER TABLE users ADD COLUMN IF NOT EXISTS groups JSONB;

-- Managed accounts
ALTER TABLE users ADD COLUMN IF NOT EXISTS managed_accounts JSONB;

-- Indexes for new fields
CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id);
CREATE INDEX IF NOT EXISTS idx_users_user_type ON users(user_type);
CREATE INDEX IF NOT EXISTS idx_users_tag ON users(tag);
CREATE INDEX IF NOT EXISTS idx_users_signup_application ON users(signup_application);

-- =============================================
-- ORGANIZATIONS table expansion
-- =============================================

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS logo VARCHAR(200);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS logo_dark VARCHAR(200);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS password_salt VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS password_options JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS password_obfuscator_type VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS password_obfuscator_key VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS password_expire_days INT NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS default_password VARCHAR(200);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS master_password VARCHAR(200);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS master_verification_code VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS user_types JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS country_codes JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS default_application VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS init_score INT NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS languages JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS theme_data JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS account_menu VARCHAR(20);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS enable_soft_deletion BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS is_profile_public BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS use_email_as_username BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS enable_tour BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS disable_signin BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ip_restriction VARCHAR(200);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ip_whitelist VARCHAR(200);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS has_privilege_consent BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS account_items JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS nav_items JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS user_nav_items JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS widget_items JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_items JSONB;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_remember_in_hours INT NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS org_balance DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS user_balance DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS balance_credit DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS balance_currency VARCHAR(100);

-- =============================================
-- APPLICATIONS table expansion
-- =============================================

ALTER TABLE applications ADD COLUMN IF NOT EXISTS refresh_expire_in_hours INT NOT NULL DEFAULT 168;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS signup_url VARCHAR(512);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS signin_url VARCHAR(512);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS forget_url VARCHAR(512);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS terms_of_use VARCHAR(512);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS signup_html TEXT;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS signin_html TEXT;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS signup_items JSONB;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS signin_items JSONB;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS signin_methods JSONB;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS grant_types JSONB;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS providers JSONB;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS saml_reply_url VARCHAR(512);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_password BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_signin_session BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_auto_signin BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_code_signin BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_saml_compress BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_saml_c14n10 BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_web_authn BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_link_with_email BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_internal_signup BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS enable_idp_signup BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS form_offset INT NOT NULL DEFAULT 0;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS form_side_html TEXT;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS form_background_url VARCHAR(512);
ALTER TABLE applications ADD COLUMN IF NOT EXISTS form_css TEXT;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS form_css_mobile TEXT;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS invitation_codes JSONB;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS default_code_expire_minutes INT NOT NULL DEFAULT 5;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS footer_text VARCHAR(512);

-- =============================================
-- New tables: Orders, Tickets, Forms
-- =============================================

CREATE TABLE IF NOT EXISTS orders (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),
    provider VARCHAR(100),
    product_name VARCHAR(100),
    product_display_name VARCHAR(255),
    quantity INT NOT NULL DEFAULT 1,
    price DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency VARCHAR(20) NOT NULL DEFAULT 'USD',
    state VARCHAR(50) NOT NULL DEFAULT 'Created',
    tag VARCHAR(100),
    invoice_url TEXT,
    payment_id VARCHAR(100),
    payment_name VARCHAR(100),
    return_url TEXT,
    user VARCHAR(100),
    plan_name VARCHAR(100),
    pricing_name VARCHAR(100),
    error_text TEXT,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX IF NOT EXISTS idx_orders_owner ON orders(owner);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders("user");
CREATE INDEX IF NOT EXISTS idx_orders_state ON orders(state);

CREATE TABLE IF NOT EXISTS tickets (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),
    ticket_type VARCHAR(50) NOT NULL DEFAULT 'general',
    subject VARCHAR(500) NOT NULL,
    content TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    priority VARCHAR(20) NOT NULL DEFAULT 'normal',
    assignee VARCHAR(100),
    reporter VARCHAR(100),
    comments JSONB,
    tags JSONB,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX IF NOT EXISTS idx_tickets_owner ON tickets(owner);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_assignee ON tickets(assignee);

CREATE TABLE IF NOT EXISTS forms (
    id VARCHAR(36) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),
    form_items JSONB,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner, name)
);

CREATE INDEX IF NOT EXISTS idx_forms_owner ON forms(owner);
