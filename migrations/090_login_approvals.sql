-- PMS-658: pending "approve this sign-in" challenges for suspicious logins.
--
-- A login flagged as suspicious (new country and/or new device, decided by
-- AuthService) does NOT mint a session. Instead one row is inserted here and a
-- single-use 6-digit code is emailed to the user; the client re-POSTs the login
-- with the code to complete it (mirrors the existing MFA re-POST flow). Only the
-- SHA-256 hash of the code is stored, so a leaked row cannot be turned back into
-- a working code. Rows are short-lived (expires_at) and single-use (consumed_at).
--
-- RLS: the 024/038 fail-closed policy loops already ran, so a table created now
-- does NOT inherit the tenant_isolation policy. Attach the same FORCE'd policy
-- explicitly (PMS-257 posture). The GUC is set transaction-locally by
-- `Database::begin_with_tenant` (src/db/pool.rs).

CREATE TABLE login_approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 hex of the emailed 6-digit code; the code itself is never stored.
    code_hash TEXT NOT NULL,
    -- Context of the flagged attempt, for the approval email and audit trail.
    country TEXT,
    device_hash TEXT,
    -- Client IP string, matching user_sessions.ip_address (VARCHAR(45)).
    ip_address VARCHAR(45),
    user_agent TEXT,
    -- Wrong-code attempts against this challenge; capped by the service.
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_approvals_user ON login_approvals(tenant_id, user_id);
CREATE INDEX idx_login_approvals_expires ON login_approvals(expires_at);

ALTER TABLE login_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON login_approvals
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
