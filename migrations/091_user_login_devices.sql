-- PMS-658: per-user set of known login devices, for the suspicious-login
-- notify-and-approve gate.
--
-- A device is identified by a client-supplied stable `device_id` (generated and
-- persisted by the SPA); only its SHA-256 hash is stored here. On login the
-- service hashes the presented device_id and treats a login from a device_hash
-- not in this table as a "new device" signal - but only once the user already
-- has >= 1 known device (the first device(s) are baseline, mirroring how the
-- first login country is recorded rather than alerted). A cleared login (either
-- not flagged, or flagged then approved) records/refreshes the device here.
--
-- Fail-open: clients that do not send a device_id contribute no device signal,
-- so the gate degrades to country-only for them (no over-gating).
--
-- RLS: same explicit FORCE'd tenant_isolation policy as login_approvals (090).

CREATE TABLE user_login_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 hex of the client-supplied device_id.
    device_hash TEXT NOT NULL,
    -- Most recent user agent seen for this device, for the approval email.
    user_agent TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id, device_hash)
);

CREATE INDEX idx_user_login_devices_user ON user_login_devices(tenant_id, user_id);

ALTER TABLE user_login_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_login_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_login_devices
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
