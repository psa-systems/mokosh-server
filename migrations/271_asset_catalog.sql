-- PMS-1492 (asset catalog + bulk order, phase 3, MR1): the catalog tables
-- the SPA's `AssetBulkCreateModal` + `/settings/asset-catalog` write
-- against, plus the weak back-link from an asset to the catalog row the
-- create flow matched.
--
-- Design doc: docs/mokosh-assets/04-templates-and-bulk-order.md
--
-- Why two tables, not one. A `model` is "the thing: Dell Latitude 5450"
-- plus the fields a catalog row knows regardless of context (warranty
-- horizon, EOL horizon, asset_type). A `template` is "a saved form
-- shape: my sales-dept Latitude 5450" plus the per-order context
-- (company, site, assigned user, tags). The create flow overlays
-- template on top of model on top of the operator's per-batch choices.
-- One table would conflate "known device" with "my saved order form"
-- and lose the deduplication the model side needs (one row per
-- manufacturer+model+type per tenant).
--
-- `assets.asset_model_id` is nullable and `ON DELETE SET NULL`. A
-- legacy asset created before this migration stays valid; a tenant
-- deleting a catalog row keeps every asset that referenced it. The
-- link is informational: the inline-edit drawer uses it to show a
-- "Model" row above Manufacturer, but the asset's own fields are the
-- source of truth for display and filter.

-- ============================================================================
-- asset_models
-- ============================================================================

-- Every FK in this migration is `DEFERRABLE INITIALLY IMMEDIATE` so the
-- tenant-data import path (`SET CONSTRAINTS ALL DEFERRED` inside the
-- wipe-and-reload transaction, migration 088) can satisfy them in any
-- insert order. Default per-statement checking is unchanged for every
-- other write. See migration 088's note: "constraints added by FUTURE
-- migrations default to NOT DEFERRABLE".
CREATE TABLE asset_models (
    id                     UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id              UUID         NOT NULL
                                        REFERENCES tenants(id) ON DELETE CASCADE
                                        DEFERRABLE INITIALLY IMMEDIATE,
    manufacturer           VARCHAR(100) NOT NULL,
    model                  VARCHAR(100) NOT NULL,
    -- `ON DELETE NO ACTION` rather than `RESTRICT`: both block the
    -- deletion of a referenced asset_types row, but only NO ACTION
    -- respects the DEFERRABLE clause below. The tenant-data import
    -- (`SET CONSTRAINTS ALL DEFERRED`) wipes every tenant table in any
    -- order; RESTRICT would fire mid-transaction regardless.
    asset_type_id          UUID         NOT NULL
                                        REFERENCES asset_types(id) ON DELETE NO ACTION
                                        DEFERRABLE INITIALLY IMMEDIATE,
    -- Each default is OPTIONAL: a row may know only manufacturer + model
    -- and let the operator fill the rest at create time. `warranty_months`
    -- + `end_of_life_months` are per-order horizons the SPA adds to the
    -- purchase date; the asset row stores the resolved dates, not the
    -- offset.
    warranty_months        INTEGER,
    end_of_life_months     INTEGER,
    default_department     VARCHAR(100),
    default_license_vendor VARCHAR(150),
    default_tags           TEXT[],
    -- `specs` is open-ended (cpu, ram_gb, disk_gb, screen_in, ...) so a
    -- tenant can grow the shape without a migration. The SPA chooses
    -- which keys to render on the model-manage page.
    specs                  JSONB        NOT NULL DEFAULT '{}',
    image_url              TEXT,
    -- `source` marks who authored the row:
    --   'seeded'          - PMS-1492 MR4 seed catalog (DEFAULT tenant,
    --                       copied on new-tenant creation).
    --   'tenant_authored' - manually created via POST /asset-models.
    --   'auto_derived'    - PMS-1492 MR3 signature detector (not yet;
    --                       value reserved so MR3 does not need to
    --                       widen the CHECK).
    source                 VARCHAR(20)  NOT NULL CHECK (source IN ('seeded', 'tenant_authored', 'auto_derived')),
    -- `uses_count` is maintained by the service layer on create (+N via
    -- bulk-create's post-insert step, +1 via single POST /assets with
    -- `asset_model_id` set). The typeahead orders by this DESC so the
    -- tenant's most-used models rise.
    uses_count             INTEGER      NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- One canonical row per (tenant, manufacturer-case-insensitive,
-- model-case-insensitive, type). The lower() dedup is the point:
-- "dell latitude 5450" (Workstation) and "Dell Latitude 5450"
-- (Workstation) collide intentionally. A UNIQUE INDEX rather than a
-- UNIQUE constraint because Postgres allows function expressions
-- here but not in the inline constraint shape.
CREATE UNIQUE INDEX idx_asset_models_unique_shape
    ON asset_models (tenant_id, lower(manufacturer), lower(model), asset_type_id);

CREATE INDEX idx_asset_models_tenant_uses
    ON asset_models (tenant_id, uses_count DESC);

-- Trigram GIN for the typeahead. The expression matches what
-- `search_models_for_typeahead` SELECTs on so the planner can use the
-- index without re-casting at query time.
CREATE INDEX idx_asset_models_manufacturer_trgm
    ON asset_models
    USING gin ((lower(manufacturer || ' ' || model)) gin_trgm_ops);

ALTER TABLE asset_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_models FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_models
    USING (tenant_id::text = current_setting('app.current_tenant', TRUE))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', TRUE));

-- PMS-1265: the app role is the writer; the migrator role is a superset
-- in the hosted deployments, so the grant lands where the service runs.
GRANT SELECT, INSERT, UPDATE, DELETE ON asset_models TO mokosh_app;

COMMENT ON TABLE asset_models IS
    'PMS-1492 phase 3 MR1: catalog of known device models the Create / Bulk Create flow matches against.';

-- ============================================================================
-- asset_templates
-- ============================================================================

CREATE TABLE asset_templates (
    id                       UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id                UUID         NOT NULL
                                          REFERENCES tenants(id) ON DELETE CASCADE
                                          DEFERRABLE INITIALLY IMMEDIATE,
    name                     VARCHAR(150) NOT NULL,
    asset_model_id           UUID         NOT NULL
                                          REFERENCES asset_models(id) ON DELETE CASCADE
                                          DEFERRABLE INITIALLY IMMEDIATE,
    -- Per-order context the template fills in on top of the model's
    -- defaults. Each is optional; a template MAY be as thin as a model
    -- + a name ("Sales Latitude") when the operator wants the model
    -- preserved but no per-order fields.
    company_id               UUID REFERENCES companies(id)   ON DELETE CASCADE
                                          DEFERRABLE INITIALLY IMMEDIATE,
    site_id                  UUID REFERENCES sites(id)       ON DELETE SET NULL
                                          DEFERRABLE INITIALLY IMMEDIATE,
    default_assigned_user_id UUID REFERENCES users(id)       ON DELETE SET NULL
                                          DEFERRABLE INITIALLY IMMEDIATE,
    department               VARCHAR(100),
    tags                     TEXT[],
    notes                    TEXT,
    license_seat_count       INTEGER,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- `created_by` is informational; losing the user does not lose
    -- the template.
    created_by               UUID REFERENCES users(id)       ON DELETE SET NULL
                                          DEFERRABLE INITIALLY IMMEDIATE,
    uses_count               INTEGER      NOT NULL DEFAULT 0
);

-- UNIQUE INDEX (not inline constraint) for the same reason as
-- `idx_asset_models_unique_shape` above.
CREATE UNIQUE INDEX idx_asset_templates_unique_name
    ON asset_templates (tenant_id, lower(name));

CREATE INDEX idx_asset_templates_tenant_recent
    ON asset_templates (tenant_id, updated_at DESC);

ALTER TABLE asset_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_templates
    USING (tenant_id::text = current_setting('app.current_tenant', TRUE))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', TRUE));

GRANT SELECT, INSERT, UPDATE, DELETE ON asset_templates TO mokosh_app;

COMMENT ON TABLE asset_templates IS
    'PMS-1492 phase 3 MR1: saved (model + per-order context) shape the Bulk Create modal starts from.';

-- ============================================================================
-- assets.asset_model_id
-- ============================================================================
--
-- Weak back-link: `ON DELETE SET NULL` keeps the asset when its catalog
-- row goes. The create flow sets this when it matches a catalog row on
-- (manufacturer, model, asset_type_id); the operator typing a new model
-- that does not match leaves it NULL. A follow-up MR teaches the create
-- flow to also create the matching catalog row with `source =
-- 'auto_derived'` so the next asset of the same shape finds a hit.

ALTER TABLE assets
    ADD COLUMN asset_model_id UUID REFERENCES asset_models(id) ON DELETE SET NULL
    DEFERRABLE INITIALLY IMMEDIATE;

CREATE INDEX idx_assets_asset_model_id
    ON assets(asset_model_id)
    WHERE asset_model_id IS NOT NULL;
