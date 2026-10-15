-- PMS-1492 (asset catalog + bulk order, phase 3, MR4): seed catalog
-- rows for the DEFAULT tenant.
--
-- The copy_default_config path in TenantService re-emits these rows
-- into every new tenant (re-linked against the new tenant's asset_types
-- by name). The rows here are intentionally a short, mainstream set
-- rather than exhaustive: a tenant can add its own via POST
-- /api/v1/asset-models when they encounter an unknown model. Over time
-- the signature detector (PMS-1492 MR3) will also surface patterns and
-- the operator can convert them to tenant-authored rows.
--
-- Design doc: docs/mokosh-assets/04-templates-and-bulk-order.md
--
-- Warranty / EOL horizons are conservative defaults based on vendor
-- standard warranty periods (36 months for business laptops / 60 for
-- end-of-life). The operator can tweak per row via PUT /asset-models.
--
-- `asset_type_id` is resolved by name against the default tenant's
-- `asset_types` seeded in migration 023.

INSERT INTO asset_models
    (tenant_id, manufacturer, model, asset_type_id, warranty_months, end_of_life_months, source)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    model_set.manufacturer,
    model_set.model,
    at.id,
    model_set.warranty_months,
    model_set.end_of_life_months,
    'seeded'
FROM (
    VALUES
        -- Dell laptops
        ('Dell',       'Latitude 5450',       'Laptop',         36, 60),
        ('Dell',       'Latitude 7450',       'Laptop',         36, 60),
        ('Dell',       'XPS 13',              'Laptop',         12, 60),
        ('Dell',       'XPS 15',              'Laptop',         12, 60),
        ('Dell',       'Precision 5570',      'Laptop',         36, 72),
        ('Dell',       'Inspiron 15 3000',    'Laptop',         12, 48),
        -- Dell workstations
        ('Dell',       'OptiPlex 7010',       'Workstation',    36, 60),
        ('Dell',       'OptiPlex Micro 7020', 'Workstation',    36, 60),
        -- Dell servers
        ('Dell',       'PowerEdge R740',      'Server',         36, 84),
        ('Dell',       'PowerEdge R760',      'Server',         36, 84),
        -- HP laptops
        ('HP',         'EliteBook 840 G10',   'Laptop',         36, 60),
        ('HP',         'EliteBook 860 G10',   'Laptop',         36, 60),
        ('HP',         'ProBook 450 G10',     'Laptop',         12, 48),
        ('HP',         'ZBook Fury 16 G10',   'Laptop',         36, 72),
        -- HP workstations
        ('HP',         'ProDesk 400 G9',      'Workstation',    36, 60),
        ('HP',         'EliteDesk 800 G9',    'Workstation',    36, 60),
        -- HP servers
        ('HP',         'ProLiant DL380 Gen11','Server',         36, 84),
        -- Lenovo laptops
        ('Lenovo',     'ThinkPad T14 Gen 4',  'Laptop',         36, 60),
        ('Lenovo',     'ThinkPad X1 Carbon',  'Laptop',         36, 60),
        ('Lenovo',     'ThinkPad L14 Gen 4',  'Laptop',         12, 48),
        -- Lenovo workstations
        ('Lenovo',     'ThinkCentre M70z',    'Workstation',    36, 60),
        ('Lenovo',     'ThinkStation P360',   'Workstation',    36, 72),
        -- Apple
        ('Apple',      'MacBook Pro 14"',     'Laptop',         12, 72),
        ('Apple',      'MacBook Pro 16"',     'Laptop',         12, 72),
        ('Apple',      'MacBook Air 13"',     'Laptop',         12, 72),
        ('Apple',      'MacBook Air 15"',     'Laptop',         12, 72),
        ('Apple',      'iMac 24"',            'Workstation',    12, 72),
        ('Apple',      'Mac Mini',            'Workstation',    12, 72),
        ('Apple',      'iPhone 15',           'Mobile Device',  12, 48),
        ('Apple',      'iPhone 15 Pro',       'Mobile Device',  12, 48),
        ('Apple',      'iPad Air',            'Mobile Device',  12, 48),
        -- Microsoft
        ('Microsoft',  'Surface Laptop 5',    'Laptop',         12, 48),
        ('Microsoft',  'Surface Pro 9',       'Laptop',         12, 48),
        -- Samsung
        ('Samsung',    'Galaxy S24',          'Mobile Device',  24, 48),
        ('Samsung',    'Galaxy Tab S9',       'Mobile Device',  12, 48),
        -- Network
        ('Ubiquiti',   'UniFi 6 Pro',         'Network Device', 24, 60),
        ('Ubiquiti',   'UniFi Dream Machine', 'Network Device', 12, 60),
        ('Cisco',      'Catalyst 9300',       'Network Device', 60, 120),
        ('Fortinet',   'FortiGate 60F',       'Network Device', 36, 60),
        ('Meraki',     'MX67',                'Network Device', 36, 60),
        -- Printers
        ('HP',         'LaserJet Pro M404dn', 'Printer',        12, 60),
        ('Brother',    'HL-L2370DW',          'Printer',        12, 60),
        ('Canon',      'imageCLASS MF445dw',  'Printer',        12, 60)
) AS model_set(manufacturer, model, type_name, warranty_months, end_of_life_months)
JOIN asset_types at
    ON at.tenant_id = '00000000-0000-0000-0000-000000000001'::uuid
   AND at.name = model_set.type_name
   AND at.parent_type_id IS NULL
-- Idempotency: a re-run (or a migration that already landed) must not
-- duplicate. The ON CONFLICT target matches the UNIQUE INDEX
-- expression list on asset_models (migration 271); the ON CONFLICT
-- ON CONSTRAINT shape does not work against an index (only against a
-- declared constraint), so the expression form is required.
ON CONFLICT (tenant_id, lower(manufacturer), lower(model), asset_type_id) DO NOTHING;
