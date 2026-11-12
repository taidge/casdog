-- Explicit tenant/application approval for the passive OpenClaw OTLP receiver.
-- Exporter credentials are independent of browser JWTs and never stored in clear.
CREATE TABLE telemetry_receivers (
    id TEXT PRIMARY KEY,
    organization VARCHAR(100) NOT NULL REFERENCES organizations(name),
    provider_id VARCHAR(36) NOT NULL UNIQUE REFERENCES providers(id) ON DELETE CASCADE,
    application_id VARCHAR(36) NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    auth_mode TEXT NOT NULL CHECK (auth_mode IN ('token','source_ip')),
    token_hash TEXT UNIQUE,
    allowed_sources CIDR[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    approved_by TEXT NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    batch_count INTEGER NOT NULL DEFAULT 0 CHECK (batch_count >= 0),
    byte_count BIGINT NOT NULL DEFAULT 0 CHECK (byte_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (NOT enabled OR auth_mode <> 'token' OR (token_hash IS NOT NULL AND token_hash ~ '^[0-9a-f]{64}$')),
    CHECK (auth_mode <> 'source_ip' OR cardinality(allowed_sources) > 0),
    CHECK (cardinality(allowed_sources) <= 16)
);
CREATE INDEX telemetry_receivers_tenant ON telemetry_receivers(organization);
-- Keep the original protobuf as well as the canonical Entry JSON. Unknown wire
-- fields from newer exporters must not be silently discarded by this version.
CREATE TABLE telemetry_ingestions (
    id TEXT PRIMARY KEY,
    receiver_id TEXT REFERENCES telemetry_receivers(id) ON DELETE SET NULL,
    organization VARCHAR(100) NOT NULL,
    signal TEXT NOT NULL CHECK(signal IN ('traces','metrics','logs')),
    item_count INTEGER NOT NULL CHECK(item_count >= 0),
    protobuf BYTEA NOT NULL CHECK(octet_length(protobuf) <= 4194304),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX telemetry_ingestions_tenant ON telemetry_ingestions(organization,created_at);
