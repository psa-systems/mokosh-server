-- Soft revoke: a revoked key stays listed (with when) but never authenticates.
-- last_used_at already exists from 003_auth.sql.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
