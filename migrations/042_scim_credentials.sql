-- SCIM Bearer access tokens may be JWTs much larger than database passwords.
-- Source-specific service validation still bounds SCIM credentials to 16 KiB
-- and retains the existing database/LDAP/Keycloak credential bounds.
ALTER TABLE syncers ALTER COLUMN "user" TYPE TEXT;
ALTER TABLE syncers ALTER COLUMN password TYPE TEXT;
