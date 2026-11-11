-- Local owner namespaces and object keys exceed the old 100-character identifier limit.
-- Runtime authorization still limits Local providers to the operator-controlled tenant root.
ALTER TABLE providers ALTER COLUMN bucket TYPE TEXT;
ALTER TABLE resources ALTER COLUMN name TYPE TEXT;
