-- Products
CREATE TABLE IF NOT EXISTS products (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    image VARCHAR(500) DEFAULT '',
    detail TEXT DEFAULT '',
    currency VARCHAR(10) DEFAULT 'USD',
    price DOUBLE PRECISION NOT NULL DEFAULT 0,
    quantity INTEGER NOT NULL DEFAULT -1,
    sold INTEGER NOT NULL DEFAULT 0,
    tag VARCHAR(100) DEFAULT '',
    state VARCHAR(50) NOT NULL DEFAULT 'active',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);

-- Plans
CREATE TABLE IF NOT EXISTS plans (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    price_per_month DOUBLE PRECISION NOT NULL DEFAULT 0,
    price_per_year DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency VARCHAR(10) DEFAULT 'USD',
    role VARCHAR(100) DEFAULT '',
    options TEXT DEFAULT '[]',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);

-- Pricings
CREATE TABLE IF NOT EXISTS pricings (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    plans TEXT DEFAULT '[]',
    trial_duration INTEGER DEFAULT 0,
    application VARCHAR(100) DEFAULT '',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);

-- Subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    user_id VARCHAR(100) NOT NULL,
    plan_id VARCHAR(100) NOT NULL,
    pricing_id VARCHAR(100) DEFAULT '',
    start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_date TIMESTAMPTZ,
    period VARCHAR(50) DEFAULT 'monthly',
    state VARCHAR(50) NOT NULL DEFAULT 'active',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);

-- Payments
CREATE TABLE IF NOT EXISTS payments (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    provider_id VARCHAR(100) DEFAULT '',
    payment_type VARCHAR(50) NOT NULL DEFAULT 'pay-pal',
    product_id VARCHAR(100) DEFAULT '',
    product_name VARCHAR(255) DEFAULT '',
    user_id VARCHAR(100) DEFAULT '',
    amount DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency VARCHAR(10) DEFAULT 'USD',
    state VARCHAR(50) NOT NULL DEFAULT 'created',
    message TEXT DEFAULT '',
    invoice_url VARCHAR(500) DEFAULT '',
    return_url VARCHAR(500) DEFAULT '',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);

-- Transactions
CREATE TABLE IF NOT EXISTS transactions (
    id VARCHAR(100) PRIMARY KEY,
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    provider_id VARCHAR(100) DEFAULT '',
    category VARCHAR(100) DEFAULT '',
    transaction_type VARCHAR(50) NOT NULL DEFAULT 'balance',
    product_id VARCHAR(100) DEFAULT '',
    user_id VARCHAR(100) DEFAULT '',
    application VARCHAR(100) DEFAULT '',
    amount DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency VARCHAR(10) DEFAULT 'USD',
    balance DOUBLE PRECISION NOT NULL DEFAULT 0,
    state VARCHAR(50) NOT NULL DEFAULT 'created',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner, name)
);
