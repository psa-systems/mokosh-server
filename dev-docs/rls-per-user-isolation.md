# Per-user data isolation: table classification and the system-shared class

Status: living document for the PMS-255 epic (per-user data isolation via
personal tenants). This file is the home for the lookup-table **classification**
(PMS-259) and the **system-shared read-only class** mechanism. Layers that flip
RLS fail-closed (PMS-257), plumb the GUC on every path (PMS-256), cover the six
tenant-less tables (PMS-258), and backfill (PMS-263) are tracked in their own
issues; this doc records only what PMS-259 owns plus the shared vocabulary.

## Isolation model (decided in PMS-255)

Each Bunyip user is placed in their own `kind='personal'` tenant
(`TenantService::ensure_personal_tenant`, called from `place_bunyip_user`,
`src/modules/auth/middleware.rs`). The existing `tenant_id` boundary therefore
becomes the per-user boundary. There is no shared business data. Future
`kind='org'` tenants plus a teams / ACL layer will add collaboration on top of
this primitive without reworking it.

## Table classes

Every table is exactly one of:

- **business** - user-owned operational rows (tickets, time entries, invoices,
  assets, ...). Isolated per personal tenant. Created by the user at runtime;
  never seeded.
- **editable-lookup** - user-editable reference / configuration rows (statuses,
  priorities, types, work types, tax rates, ...). Isolated per personal tenant
  **and seeded once per tenant at provisioning** so a fresh user starts with a
  sensible default set instead of empty lists.
- **system-shared** - genuinely non-editable, globally shared rows (reserved;
  none exist yet). One physical row, `tenant_id IS NULL`, readable by every
  tenant, writable only by a privileged session. Reserved structurally by
  PMS-259; see "System-shared class" below.
- **auth / infra** - identity and platform rows (`tenants`, `users`,
  `user_sessions`, OAuth/SSO crates). Scoped by their own keys; out of the
  lookup-seeding scope.

## Editable-lookup classification (PMS-259)

These tables are **editable-lookup** and are seeded per tenant by
`TenantService::copy_default_config` (src/modules/tenants/service.rs), copying
the migration-`023` default-tenant rows and re-scoping them to the new tenant.
Inter-lookup foreign keys are re-linked to the new tenant's freshly copied rows
by name.

| Table | Seeded | FK re-link on copy |
| --- | --- | --- |
| `business_hours` | yes | - |
| `ticket_statuses` | yes | - |
| `ticket_priorities` | yes | - |
| `ticket_types` | yes | - |
| `ticket_categories` | yes | self `parent_id` (parents then children) |
| `ticket_queues` | yes | team / sla links left NULL (tenant-specific) |
| `work_types` | yes | - |
| `task_statuses` | yes | - |
| `asset_types` | yes (top-level) | - |
| `time_rounding_rules` | yes | - |
| `tax_rates` | yes | - |
| `kb_categories` | yes | self `parent_id` (parents then children) |
| `rate_cards` | yes | - |
| `rate_card_items` | yes | `rate_card_id`, `work_type_id` by name |
| `sla_policies` | yes | `business_hours_id` by name |
| `sla_targets` | yes | `sla_policy_id`, `priority_id` by name |
| `module_config` | yes | - |
| `notification_templates` (worker subset) | yes | - |
| `notification_rules` (worker subset) | yes | `template_id` by (event, channel) |

The seed is **idempotent**: `copy_default_config` skips entirely when the tenant
already holds `ticket_statuses` rows, and runs in a single transaction so a
tenant is either fully seeded or not at all.

### Borderline tables (confirmed classification)

- `business_hours` - **editable-lookup**. Despite feeling like infrastructure it
  is per-tenant, user-editable (timezone, weekly schedule), and seeded. A future
  global maintenance-window calendar would be a separate system-shared table,
  not this one.
- `payment_gateway_configs` - **business**, NOT a lookup. It holds per-tenant
  secrets (encrypted with `ENCRYPTION_KEY`); it is created by the user when they
  connect a gateway and must never be seeded or shared. Stays isolated.
- `email_mailboxes` - **business**, NOT a lookup. Per-tenant credentials /
  connection settings created at runtime; not seeded, not shared.

## System-shared class (PMS-259, structural)

Reserved for future non-editable global rows (e.g. system statuses, maintenance
windows). Implemented by `migrations/038_system_shared_class.sql`. **No table
opts in yet and no system-shared row exists**; every lookup `tenant_id` column
is still `NOT NULL`, so the mechanism is a no-op for current data.

Mechanism:

1. **Sentinel**: `tenant_id IS NULL` means "global / system-shared".
2. **Read (RLS)**: the `tenant_isolation` policy on every `tenant_id` table is
   recreated with `tenant_id IS NULL OR tenant_id = <current-tenant match>`, so
   a global row is visible to every tenant. (PMS-257 owns flipping the tenant
   match fail-closed and adding WITH CHECK; the `IS NULL` read clause is owned
   here.)
3. **Write guard (DB)**: trigger function `mokosh_guard_system_shared_row()`
   rejects any INSERT / UPDATE / DELETE touching a `tenant_id IS NULL` row
   unless the session sets `app.allow_system_writes = 'on'` (reserved for the
   migration / super-admin role). Raises SQLSTATE `42501`
   (`insufficient_privilege`).
4. **Write guard (app)**: application code must never write a system-shared row
   from an ordinary request path. Only an explicit super-admin / migration path
   sets `app.allow_system_writes` and writes globals. Ordinary lookup CRUD
   always writes `tenant_id = <caller tenant>`, so it can never produce a
   global row.
5. **Opt-in**: a table joins the class later with
   `SELECT mokosh_enable_system_shared('<table>');` which drops the `tenant_id`
   NOT NULL constraint and attaches the `guard_system_shared_row` trigger. The
   global rows are then inserted from a privileged
   (`app.allow_system_writes = 'on'`) session.

This keeps genuinely global config from being needlessly duplicated per tenant
while preserving strict per-user isolation for everything editable.
