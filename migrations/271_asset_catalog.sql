-- PMS-1488 (asset catalog, phase 3): per-tenant catalog of device
-- models + templates on top of them, plus the weak FK from `assets`
-- back to the catalog row.
--
-- Background. The assets table carries `manufacturer` + `model` as
-- free text. A corporation that orders twelve Dell Latitude 5450s
-- today retypes the pair twelve times; the second order next quarter
-- retypes it another twelve. The redesign's goal (see
-- docs/mokosh-assets/04-templates-and-bulk-order.md) is one typeahead
-- against a catalog that knows the model + the fields its purchase
-- usually fills (warranty months, end-of-life months, default
-- department, default license vendor, default tags, specs blob).
--
-- `asset_templates` is a model + context: "my sales-dept Latitude
-- 5450". The create flow pulls model fields first, then overlays
-- the template's context fields on top.
--
-- `assets.asset_model_id` is a nullable FK: a legacy asset without a
-- catalog row stays valid; `ON DELETE SET NULL` keeps the asset row
-- live when a catalog row is deleted (deliberate: deleting a model
-- should not nuke the historical assets that referenced it).

CREATE TABLE asset_models (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    manufacturer         VARCHAR(100) NOT NULL,
    model                VARCHAR(100) NOT NULL,
    asset_type_id        UUID         NOT NULL REFERENCES asset_types(id) ON DELETE RESTRICT,
    -- Pre-fill defaults, each optional. A row may know only the
    -- (manufacturer, model) pair and let the operator fill the rest
    -- at create time.
    warranty_months      INTEGER,
    end_of_life_months   INTEGER,
    default_department   VARCHAR(100),
    default_license_vendor VARCHAR(150),
    default_tags         TEXT[] NOT NULL DEFAULT '{}',
    specs                JSONB  NOT NULL DEFAULT '{}',   -- cpu, ram_gb, disk_gb, screen_in, ...
    image_url            TEXT,
    -- Where this row came from. `seeded` is reserved for a future
    -- default-tenant catalog that a tenant inherits via
    -- `seed_default_config`. `tenant_authored` is a manual CRUD
    -- insert; `auto_derived` is the signature-detector banner's
    -- opt-in on a repeated (manufacturer, model, asset_type_id)
    -- signature. The CHECK keeps the enum closed.
    source               VARCHAR(20) NOT NULL
        CHECK (source IN ('seeded', 'tenant_authored', 'auto_derived')),
    uses_count           INTEGER     NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One row per (manufacturer, model, asset_type_id) triple within a
    -- tenant. Case-insensitive on both strings so "Dell"/"dell" collide.
    UNIQUE (tenant_id, asset_type_id, lower(manufacturer), lower(model))
);

-- Typeahead reads the catalog by the operator's own usage: most-used
-- rises. A plain btree on (tenant_id, uses_count DESC) answers the no-
-- query case.
CREATE INDEX idx_asset_models_tenant_uses
    ON asset_models (tenant_id, uses_count DESC);

-- Freely typed `q=` on the typeahead matches against manufacturer || model
-- (case-insensitive). pg_trgm matches the shape every other catalog in
-- this repo uses (companies, contacts, tickets, assets); see
-- `migrations/011_assets.sql:40` for the asset-side precedent.
CREATE INDEX idx_asset_models_manufacturer_trgm
    ON asset_models USING gin ((lower(manufacturer || ' ' || model)) gin_trgm_ops);

ALTER TABLE asset_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_models FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_models
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON asset_models TO mokosh_app;

COMMENT ON TABLE asset_models IS
    'PMS-1488: per-tenant catalog of device models. The bulk-create flow and the Create form read it via /asset-models?q=; the signature-detector banner writes an auto_derived row when the tenant produces N identical creates in the last 7 days.';
COMMENT ON COLUMN asset_models.source IS
    'seeded | tenant_authored | auto_derived. Reserved: `seeded` for a default-tenant catalog that `seed_default_config` copies; `auto_derived` for the signature banner''s opt-in; `tenant_authored` for an admin CRUD insert.';

-- A template is a frozen snapshot of (model + context). The context
-- fields are the ones that are the SAME across every purchase from
-- this template; the per-row fields (serial, hostname, mac, ip, asset
-- tag) live on each `BulkSerial` the operator pastes in.
CREATE TABLE asset_templates (
    id                       UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id                UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                     VARCHAR(150) NOT NULL,
    asset_model_id           UUID         NOT NULL REFERENCES asset_models(id) ON DELETE CASCADE,
    company_id               UUID REFERENCES companies(id) ON DELETE SET NULL,
    site_id                  UUID REFERENCES sites(id) ON DELETE SET NULL,
    default_assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    department               VARCHAR(100),
    tags                     TEXT[] NOT NULL DEFAULT '{}',
    notes                    TEXT,
    license_seat_count       INTEGER,
    uses_count               INTEGER NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by               UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (tenant_id, lower(name))
);

CREATE INDEX idx_asset_templates_tenant_recent
    ON asset_templates (tenant_id, updated_at DESC);

ALTER TABLE asset_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_templates
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON asset_templates TO mokosh_app;

COMMENT ON TABLE asset_templates IS
    'PMS-1488: a saved (model + context) shape the bulk-create flow fans N rows out of. One tenant typically authors three or four templates per model family.';

-- Weak FK from assets back to the catalog row that provided the
-- (manufacturer, model) pair. `ON DELETE SET NULL` so deleting a
-- catalog row does not nuke the historical assets that referenced
-- it; the row stays with its freetext manufacturer + model intact.
ALTER TABLE assets ADD COLUMN asset_model_id UUID REFERENCES asset_models(id) ON DELETE SET NULL;
CREATE INDEX idx_assets_asset_model_id
    ON assets(asset_model_id) WHERE asset_model_id IS NOT NULL;
