-- Casdoor 2026 resource envelopes retain protocol field names and nested MCP tool schemas.
-- Only the closed resource kinds below can be stored; owner/name are the durable identity.
CREATE TABLE IF NOT EXISTS casdoor_objects (
    kind TEXT NOT NULL CHECK (kind IN ('agent', 'entry', 'key', 'server', 'integration')),
    owner VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, owner, name),
    CHECK (document->>'owner' = owner AND document->>'name' = name)
);
CREATE INDEX IF NOT EXISTS casdoor_objects_listing ON casdoor_objects(kind, owner, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS casdoor_objects_access_key ON casdoor_objects((document->>'accessKey')) WHERE kind = 'key';
CREATE INDEX IF NOT EXISTS casdoor_objects_entry_provider ON casdoor_objects(owner, (document->>'provider')) WHERE kind='entry';
