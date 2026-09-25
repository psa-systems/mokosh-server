-- CRM status model: one row per system an RMM tracks and an append-only
-- log of observations against it.
--
-- Two tables rather than one because a monitored system is a durable
-- record (name, first / last seen, retirement) and an observation is a
-- one-shot event (this check, at this instant, said this). Widening a
-- single events table with the system's identity would repeat the same
-- name on every write and make retirement invisible; keeping them
-- separate lets the current status resolve to "the latest observation for
-- this system and check kind" without a second concept for "the system".
--
-- `check_kind` and `outcome` are open TEXT with CHECK constraints so a
-- future kind (disk / patch / antivirus) lands in this same table without
-- a per-kind migration, and the constraint keeps a typo out of the wire.
-- Backup is the first kind because it is the one the reporting epic
-- names as the priority.
--
-- Idempotency lives on the observations table: a delivery replayed with
-- the same (monitored_system_id, check_kind, observed_at) triple is a
-- no-op through `ON CONFLICT DO NOTHING`. The ingest handler relies on
-- that, so a network retry from Tactical RMM does not add a second row.
--
-- RLS: both tables are tenant-scoped so the standard tenant isolation
-- policy applies. Every column that gates a read carries the tenant_id
-- so cross-tenant leaks fail closed at the pool.
--
-- Retention: no cleanup runs in this migration. A later change (part of
-- the trend-reports work) documents and enforces the 13-month retention;
-- the append-only shape is what lets that job be written at all.

BEGIN;

CREATE TABLE monitored_systems (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_id         UUID        NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    external_source    TEXT        NOT NULL,
    external_id        TEXT        NOT NULL,
    name               TEXT        NOT NULL,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, external_source, external_id)
);

CREATE INDEX monitored_systems_company_idx
    ON monitored_systems (tenant_id, company_id)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE monitored_systems IS
    'One row per system an external monitoring source tracks. Company-scoped so a status query filters like every other CRM read.';
COMMENT ON COLUMN monitored_systems.external_source IS
    'Which system reported this. Open TEXT: tactical_rmm is the first, and the wider check gates land here as new sources.';
COMMENT ON COLUMN monitored_systems.external_id IS
    'Stable identifier at the source (e.g. the Tactical RMM agent_id). Combined with external_source for idempotent upserts.';

CREATE TABLE status_observations (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    company_id            UUID        NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    monitored_system_id   UUID        NOT NULL REFERENCES monitored_systems(id) ON DELETE CASCADE,
    check_kind            TEXT        NOT NULL,
    outcome               TEXT        NOT NULL,
    observed_at           TIMESTAMPTZ NOT NULL,
    payload               JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (check_kind IN ('backup', 'disk', 'patch', 'antivirus')),
    CHECK (outcome IN ('success', 'warning', 'failure', 'unknown')),
    UNIQUE (monitored_system_id, check_kind, observed_at)
);

-- The read shape every current-status query uses: newest first, filtered
-- by system and kind. A LIMIT 1 on this index answers "what does this
-- check say right now".
CREATE INDEX status_observations_current_idx
    ON status_observations (monitored_system_id, check_kind, observed_at DESC);

-- The company view: every observation on every system a company owns,
-- so a per-company backup rollup does not scan every tenant's rows.
CREATE INDEX status_observations_company_kind_idx
    ON status_observations (tenant_id, company_id, check_kind, observed_at DESC);

COMMENT ON TABLE status_observations IS
    'Append-only history of check outcomes. The latest row per (system, check_kind) is the current status; older rows keep the trend readable.';
COMMENT ON COLUMN status_observations.check_kind IS
    'What was checked (backup | disk | patch | antivirus). Open TEXT with a CHECK so a typo does not land silently and a new kind lands without a migration per kind.';
COMMENT ON COLUMN status_observations.outcome IS
    'What the check said (success | warning | failure | unknown). unknown covers a delivery whose payload could not be classified.';
COMMENT ON COLUMN status_observations.observed_at IS
    'When the source observed the outcome, not when we received it. Also the third leg of the idempotency triple.';

-- RLS: both tables sit inside the standard tenant-scoped surface. Enable
-- AND FORCE (the 038 fail-closed loop already ran, so a table created now
-- does not inherit the policy) and give the policy a WITH CHECK so an
-- INSERT / UPDATE cannot land a row under another tenant either. The
-- shape mirrors migrations 090 / 091.
ALTER TABLE monitored_systems     ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitored_systems     FORCE  ROW LEVEL SECURITY;
ALTER TABLE status_observations   ENABLE ROW LEVEL SECURITY;
ALTER TABLE status_observations   FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON monitored_systems
    USING       (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID)
    WITH CHECK  (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);
CREATE POLICY tenant_isolation ON status_observations
    USING       (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID)
    WITH CHECK  (tenant_id = NULLIF(current_setting('app.current_tenant', TRUE), '')::UUID);

-- Grants for the app pool. The provisioner reaches new tables only when
-- the migrator owns them; naming them explicitly here keeps the app-pool
-- read working on staging, where migrations run as `mokosh`.
GRANT SELECT, INSERT, UPDATE, DELETE ON monitored_systems   TO mokosh_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON status_observations TO mokosh_app;

COMMIT;
