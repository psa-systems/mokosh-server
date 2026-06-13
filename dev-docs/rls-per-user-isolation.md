# Per-user data isolation (PMS-255) - implementation reference

Authoritative working doc for PMS-255. It exists because the epic is too broad to
execute as one task: this doc carries the ground-truth schema inventory, the chosen
model, the table classification, and the decomposition into runner-sized child issues.

Derived from a live read of `migrations/*.sql` and `src/` on 2026-06-12. Keep it
current as the child issues land.

## Decisions (resolved with the product owner)

1. Isolation model is **personal-tenant-per-user**. Each Bunyip user is placed in their
   own `tenants` row with `kind='personal'`. The existing `tenant_id` boundary becomes the
   per-user boundary; the existing `TenantId` newtype and the `024` RLS policy do the work
   once enforcement is real and nobody normal shares the default tenant. Future `kind='org'`
   tenants plus a teams/ACL layer add collaboration on top, later, without reworking the
   isolation primitive.
2. Collaboration (assignment, dispatch, manager approval, account/project managers) is
   intentionally out of scope and temporarily precluded. This is accepted, not a blocker.
   Isolation and data integrity are the absolute highest priority.
3. User-editable lookup/config tables are **isolated per user** (they ride the personal-tenant
   boundary) and **seeded once per user** at provisioning. A separate **system-shared**
   read-only class is reserved for genuinely non-editable global rows (e.g. system statuses,
   maintenance windows); no current table is populated as system-shared, the class is
   structural room for the future.

## Current state (what already exists)

- **Provisioning is largely built.** `place_bunyip_user` (`src/modules/auth/middleware.rs:506`)
  provisions a personal tenant for new users via `TenantService::ensure_personal_tenant(sub)`,
  and the PMS-243/245 backfill (`is_stuck_in_default`, `rehome_user_between_tenants`) moves
  non-admin users off the shared default tenant `Uuid::from_u128(1)` into their own. Gap:
  prove no normal user can remain in the default tenant, and that `OIDC_DEFAULT_TENANT_ID`
  is not a shared landing zone.
- **Enforcement is NOT real.** RLS (`migrations/024_triggers_and_rls.sql:55-61`) is fail-open:
  the policy reduces to `tenant_id = tenant_id` when `app.current_tenant` is unset. The GUC is
  set only inside `Database::begin_with_tenant` (`src/db/pool.rs:90`), which most read paths
  bypass in favour of a hand-written `WHERE tenant_id = $1`. The policy is `USING`-only, so it
  has no `WITH CHECK` and does not constrain INSERT/UPDATE.
- **Type-safe tenant threading is done (PMS-139).** Service methods take `TenantId`, only
  constructible from an authenticated claim via `CurrentUser::tenant()`.

## Schema inventory (76 tables, live from migrations 2026-06-12)

`tenant_id` = has the column (so the `024` RLS loop attaches to it). `user cols` = direct
user-ownership columns. `class` is the PROPOSED handling, confirm during PMS-255.4.

Classes: `business` (user-created records), `lookup` (user-editable config, isolated + seeded
per user), `auth` (identity/session), `seq` (per-tenant counters).

### Tables WITHOUT tenant_id (6) - must be fixed (PMS-255.3)

| table | pk | user cols | issue |
| --- | --- | --- | --- |
| `tenants` | id | (personal_owner_id) | root table, by design; no change |
| `user_oauth_identities` | id | user_id | CRITICAL: unique `(provider, subject)` collides across tenants; must include tenant/user scope |
| `kb_article_versions` | id | edited_by_id | add tenant_id or parent-join RLS (parent `kb_articles`) |
| `invoice_lines` | id | - | add tenant_id or parent-join RLS (parent `invoices`) |
| `rate_card_items` | id | - | add tenant_id or parent-join RLS (parent `rate_cards`) |
| `sla_targets` | id | - | add tenant_id or parent-join RLS (parent `sla_policies`) |

### Tables WITH tenant_id (70)

business: `companies` (account_manager_id), `contacts` (portal_user_id), `sites`, `tickets`
(assigned_to_id, created_by_id, last_updated_by_id), `ticket_notes` (created_by_id),
`ticket_attachments` (uploaded_by_id), `time_entries` (user_id, approved_by_id),
`active_timers` (user_id), `time_off` (user_id, approved_by_id), `user_availability` (user_id),
`appointments` (assigned_to_id), `projects` (project_manager_id), `project_phases`, `tasks`
(assigned_to_id), `task_dependencies`, `contracts`, `contract_items`, `contract_hour_balances`,
`contract_invoice_runs`, `invoices`, `payments`, `assets`, `asset_relationships`,
`configuration_items`, `credential_vault`, `asset_audit_log` (performed_by_id), `kb_articles`
(author_id), `kb_article_votes` (user_id), `notifications` (user_id), `rmm_device_mappings`,
`files` (uploaded_by_id), `audit_log` (user_id).

lookup: `ticket_queues`, `ticket_statuses`, `ticket_priorities`, `ticket_types`,
`ticket_categories`, `ticket_automation_rules`, `work_types`, `time_rounding_rules`,
`task_statuses`, `sla_policies`, `sla_notifications`, `rate_cards`, `tax_rates`, `asset_types`,
`kb_categories`, `notification_channels`, `notification_templates`, `notification_rules`,
`user_notification_preferences` (user_id), `business_hours`, `holiday_calendars`,
`on_call_schedules`, `email_mailboxes`, `email_parse_rules`, `payment_gateway_configs`,
`rmm_connections`, `rmm_alert_rules` (assign_to_id), `appointment_reminders`, `tenant_settings`,
`module_config`.

seq: `ticket_sequences`, `invoice_sequences`.

auth: `users`, `user_sessions` (user_id), `api_keys` (user_id), `password_reset_tokens`
(user_id), `tenant_invitations` (invited_by, accepted_by), `teams` (manager_id), `team_members`
(user_id).

## Decomposition (child issues of PMS-255)

Ordered by dependency. Each is a runner-sized PR.

1. **GUC plumbing - route every PSA service query through `begin_with_tenant`.** Replace raw
   `self.pool` / `db.pool().begin()` paths so every read and write sets `app.current_tenant`.
   Prerequisite for fail-closed. Modules: all 20 under `src/modules/`.
2. **Flip RLS fail-closed + add `WITH CHECK` + `BYPASSRLS` migration role.** New migration that
   rewrites the `024` policy so an unset GUC yields zero rows and writes are constrained.
   Depends on (1).
3. **Cover the 6 no-`tenant_id` tables** (table above); fix `user_oauth_identities` unique
   constraint.
4. **Per-user lookup seeding + system-shared class.** Seed `lookup` tables into each personal
   tenant at provisioning; introduce the read-only system-shared class. Depends on the
   classification above being confirmed.
5. **Fix known cross-tenant leak points.** `auth::get_user_sessions` (`service.rs:1715`,
   user_id-only), `auth::logout_all` (`service.rs:535`), `auth::find_user_placement`
   reachability (`service.rs:1413`), `invitations::newest_pending_for` exposure
   (`service.rs:152`), `tenants::list_tenants` guard (`service.rs:242`), `reports::dashboard`
   aggregates.
6. **Audit background workers + `from_trusted` escape hatches.** calendar reminder, SLA sweep,
   billing recurring, RMM ingest webhook, notification dispatcher, portal bridges
   (`portal/routes.rs:102,127,158,178,194`).
7. **Remove/redefine the `single-tenant` cargo feature + default-tenant landing audit.**
   `main.rs:94-116`, `db/tenant.rs:45-56`; prove no normal user lands in `Uuid::from_u128(1)`.
8. **Backfill migration + verification query** for existing co-mingled default-tenant rows.
   See open decision below.
9. **Per-user isolation integration test suite.** Two users in two personal tenants; assert
   every module denies cross-user read AND write; aggregates scoped; RLS fail-closed regression.

## Open decisions to confirm (do not block the analysis, but resolve before the affected issue)

- **Legacy co-mingled data ownership (PMS-255.8).** PMS-243 deliberately left co-mingled rows in
  the default tenant "put." Under strict isolation, who owns pre-existing rows? Proposed default:
  re-home each row to the tenant of its `created_by`/owner column where one exists; quarantine the
  remainder into an admin-only tenant rather than expose them. Confirm.
- **Portal identity (PMS-255.6).** Portal runs on a `contacts`-row identity (`CurrentContact`,
  company-scoped), a separate plane from `users`. Proposed default: keep portal company-scoped for
  now and revisit with the orgs work; do not force per-user isolation on portal contacts. Confirm.
- **Lookup classification.** The `business` vs `lookup` split above is a proposed default. Confirm
  the borderline config tables (`payment_gateway_configs`, `email_mailboxes`, `business_hours`)
  during PMS-255.4.
