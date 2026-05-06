-- Append-only audit log for security-relevant events.
--
-- Every authentication, token issuance, refresh rotation, password
-- change, admin action, and detected suspicious event lands here. Rows
-- are immutable: there is no UPDATE pathway in the application.
-- Long-term retention is managed by a partitioning scheme added in a
-- later migration when volume justifies it.

CREATE TABLE mokosh_auth.audit_logs (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID,
    actor_id    UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    -- Discriminant of the AuditEvent enum, e.g. "login_success",
    -- "refresh_reuse_detected", "client_disabled".
    event_kind  TEXT         NOT NULL,
    severity    TEXT         NOT NULL,
    ip          INET,
    -- The full event payload (a serialized AuditEvent) lives here so
    -- enum evolution does not require schema migrations.
    metadata    JSONB        NOT NULL DEFAULT '{}'::JSONB,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT audit_severity_chk
        CHECK (severity IN ('info', 'warning', 'critical'))
);

-- Investigations typically pivot on tenant + time, or actor + time.
CREATE INDEX audit_logs_tenant_time_idx
    ON mokosh_auth.audit_logs (tenant_id, created_at DESC);

CREATE INDEX audit_logs_actor_time_idx
    ON mokosh_auth.audit_logs (actor_id, created_at DESC)
    WHERE actor_id IS NOT NULL;

-- Critical events feed an alerting query that scans this small partial index.
CREATE INDEX audit_logs_critical_idx
    ON mokosh_auth.audit_logs (created_at DESC)
    WHERE severity = 'critical';
