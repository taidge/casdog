ALTER TABLE organizations ADD COLUMN record_retention_days INTEGER NOT NULL DEFAULT 0
    CHECK(record_retention_days >= 0 AND record_retention_days <= 365000);
CREATE INDEX IF NOT EXISTS idx_records_retention_created ON records(created_at,id);
