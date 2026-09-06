# Per-user data isolation (PMS-255) - implementation reference

Authoritative working doc for PMS-255. It exists because the epic is too broad to
execute as one task: this doc carries the ground-truth schema inventory, the chosen
model, the table classification, and the decomposition into runner-sized child issues.

Derived from a live read of `migrations/*.sql` and `src/` on 2026-06-12, and re-read
against the working tree on 2026-08-22 (PMS-847), which corrected the enforcement
section: RLS is fail-closed, and the coverage invariant is tested with an empty
allowlist. Keep it current as the child issues land.

Citations name a file and a symbol rather than a line number, because the line numbers
in the 2026-06-12 draft had all moved by the time anyone followed them.

## Decisions (resolved with the product owner)

1. Isolation model is **personal-tenant-per-user**. Each Bunyip user is placed in their
   own `tenants` row with `kind='personal'` (`TenantService::ensure_personal_tenant`,
   called from `place_bunyip_user`, `src/modules/auth/middleware.rs`). The existing
   `tenant_id` boundary becomes the per-user boundary; the existing `TenantId` newtype
   and the RLS policy (`024`, rewritten fail-closed by `038`) do the work, provided nobody
   normal shares the default tenant. Future `kind='org'` tenants plus a teams/ACL layer add
   collaboration on top, later, without reworking the isolation primitive.
2. Collaboration (assignment, dispatch, manager approval, account/project managers) is
   intentionally out of scope and temporarily precluded. This is accepted, not a blocker.
   Isolation and data integrity are the absolute highest priority.
3. User-editable lookup/config tables are **isolated per user** (they ride the personal-tenant
   boundary) and **seeded once per user** at provisioning. A separate **system-shared**
   read-only class is reserved for genuinely non-editable global rows (e.g. system statuses,
   maintenance windows); no current table is populated as system-shared, the class is
   structural room for the future. The classification and the seeding/system-shared mechanism
   are owned by PMS-259; see "Editable-lookup seeding (PMS-259)" and "System-shared class
   (PMS-259)" below.

## Current state (what already exists)

- **Provisioning is largely built.** `place_bunyip_user` (`src/modules/auth/middleware.rs`)
  provisions a personal tenant for new users via `TenantService::ensure_personal_tenant(sub)`,
  and the PMS-243/245 backfill (`is_stuck_in_default`, `rehome_user_between_tenants`) moves
  non-admin users off the shared default tenant `Uuid::from_u128(1)` into their own.
  `tests/bunyip_login.rs` pins the three cases: a self-signup user is not placed in the shared
  default tenant, a non-admin already parked there is backfilled out, and a platform
  `super_admin` legitimately stays (the default tenant is infra-only, PMS-262).
- **Enforcement is fail-closed.** `migrations/038_rls_fail_closed.sql` (PMS-257) replaced the
  fail-open `024` policy on every `tenant_id` table with

  ```sql
  USING      (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
  ```

  and ran `ENABLE` plus `FORCE ROW LEVEL SECURITY` so the table owner is not exempt either.
  With the GUC unset or empty, the comparison is `NULL` rather than true, so a read returns
  zero rows and a write is rejected (SQLSTATE `42501`). `WITH CHECK` is what stops an INSERT
  or UPDATE placing a row in another tenant, which the `USING`-only `024` policy could not do.

  The GUC is set transaction-locally by `Database::begin_with_tenant` (`src/db/pool.rs`), via
  `set_config('app.current_tenant', $1, true)`.
- **The role split is what makes the policy bite (PMS-285).** `Database` holds two pools
  (`src/db/pool.rs`): `app_pool` connects as `mokosh_app` (`NOSUPERUSER NOBYPASSRLS`) and
  serves every request, so a serving query that skips `begin_with_tenant` fail-closes to zero
  rows instead of leaking; `migrator_pool` connects as `mokosh_migrator` (`BYPASSRLS`) and is
  reserved for migrations, bootstrap, the cross-tenant workers and the pre-auth paths, each
  carrying a `// SAFETY (PMS-285` note at the call site. `scripts/check-pool-safety.nu`
  (wired into `just check`) fails a PR that adds a bare `.pool()` serving call without one.
  In dev and CI without the role split both pools are the same connection, and a superuser or
  `BYPASSRLS` role bypasses RLS unconditionally: role posture, not the policy, is what decides
  whether the backstop is live. `docs/postgres-security.md` covers the role provisioning.
- **Coverage of the invariant is tested, and the allowlist is where an exemption is decided.**
  `tests/rls_coverage.rs` (PMS-683) introspects the fully-migrated schema and lists every
  `public` table that has a `tenant_id` column but is missing RLS enabled, RLS forced, or a
  `tenant_isolation` policy. Its `ALLOWED_WITHOUT_RLS` allowlist holds one entry,
  `tenant_membership_entitlements`, whose read is pre-auth and cross-tenant and so cannot
  carry the GUC; enabling RLS there would fail-close the read to `None`, which
  `ensure_principal_usable` reads as "no entitlement row, never lock anybody out" and would
  pass every suspended tenant. Read the entry's own comment for the full reason.

  What the near-empty allowlist guarantees, and the reason it is the useful fact for anyone
  adding a table: **a new table with a `tenant_id` column whose migration does not enable,
  force and attach the `tenant_isolation` policy fails
  `every_tenant_table_has_rls_or_is_allowlisted` outright.** There is no entry to hide behind.
  Copy the three statements from an existing migration (`105_form_definition_drafts.sql` is
  the shortest current example) into the new one. The test's second assertion runs the other
  way: an allowlisted table that has since gained RLS must be deleted from the list, so the
  list cannot rot back into cover.

  PMS-1040 is why an exemption belongs in that list and nowhere else.
  `tenant_membership_entitlements` was declared exempt in migration 154's header and again at
  the call site, and the one list that enforces anything was never told, so the guard read the
  table as an oversight rather than a decision. A rule recorded only in prose is not a rule.
- **Behaviour is tested too, not just schema shape.** `tests/rls_isolation.rs` and
  `tests/tenantless_table_rls.rs` drive the policies through a purpose-created
  `NOSUPERUSER NOBYPASSRLS` role (`#[sqlx::test]` itself connects as the superuser, which
  bypasses RLS), and `tests/rls_serving_reads.rs` pins the opposite failure: a serving read
  that reaches the app role must still return its own tenant's rows rather than fail-closing
  to an empty 200. `tests/per_user_isolation.rs` and `tests/worker_tenant_isolation.rs` cover
  the request path and the background workers.
- **Type-safe tenant threading is done (PMS-139).** Service methods take `TenantId`, only
  constructible from an authenticated claim via `CurrentUser::tenant()`.

## Schema inventory (76 tables, snapshot of migrations at 2026-06-12)

This is a dated snapshot, not a live list: migrations have added tenant tables since. The
authoritative inventory is the query in `tests/rls_coverage.rs`, which reads the migrated
schema itself; read that rather than trusting the counts below.

`tenant_id` = has the column (so the `024`/`038` RLS loops attach to it). `user cols` = direct
user-ownership columns. `class` is the handling; the editable-lookup split is confirmed by
PMS-259 (see below).

Classes: `business` (user-created records), `lookup` (user-editable config, isolated + seeded
per user), `auth` (identity/session), `seq` (per-tenant counters).

### Tables WITHOUT tenant_id - covered by migrations 041 (PMS-258) and 128 (PMS-874)

The `024`/`038` loops select `WHERE column_name = 'tenant_id'`, so these tables were skipped.
`migrations/041_rls_cover_tenantless_tables.sql` covers the five known then;
`migrations/128_rls_tenantless_child_tables.sql` covers the two added afterwards. `tenants` is
the only table here with no policy.

| table | pk | user cols | how it is isolated |
| --- | --- | --- | --- |
| `tenants` | id | (personal_owner_id) | root table, by design; no policy |
| `user_oauth_identities` | id | user_id | gained a denormalized `tenant_id` plus a tenant-scoped unique key, replacing the global `(provider, subject)` that collided across tenants; standard direct policy |
| `kb_article_versions` | id | edited_by_id | fail-closed parent-join policy (`EXISTS` over `kb_articles.tenant_id`) |
| `invoice_lines` | id | - | fail-closed parent-join policy (parent `invoices`) |
| `rate_card_items` | id | - | fail-closed parent-join policy (parent `rate_cards`) |
| `sla_targets` | id | - | fail-closed parent-join policy (parent `sla_policies`) |
| `quote_lines` | id | - | fail-closed parent-join policy (parent `quotes`), migration `128` |
| `credit_note_lines` | id | - | fail-closed parent-join policy (parent `credit_notes`), migration `128` |

The parent-join form was chosen over a denormalized column: no backfill, and no `NOT NULL`
column to keep populated on every INSERT, so no drift risk. `tests/tenantless_table_rls.rs`
pins the behaviour (per-tenant uniqueness on `user_oauth_identities`, and the parent-join
policy fail-closing on `kb_article_versions` and on `quote_lines`).

The gap this closed was not the missing policies but the missing sweep. A table in this shape
was invisible to `tests/rls_coverage.rs`, whose query required a `tenant_id` column, and
`tenantless_table_rls.rs` names tables rather than sweeping, so `quote_lines` (`092`) and
`credit_note_lines` (`122`) were both added after `041` in exactly this shape and neither made
a test go red. `every_tenantless_table_has_rls_or_is_exempt` (PMS-874) now sweeps the other
half of the schema and requires the policy on every tenantless table except the entries in its
`TENANTLESS_WITHOUT_RLS` list, each carrying its reason: `tenants`, `_sqlx_migrations`, and
(PMS-1040) `identities` and `platform_admins`, the two cross-tenant identity-plane tables that
have no tenant to scope to and no parent to join through.

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
`files` (uploaded_by_id), `audit_log` (user_id), `email_mailboxes`, `payment_gateway_configs`.

Note: `email_mailboxes` and `payment_gateway_configs` are confirmed **business**, not lookup
(per-tenant credentials/secrets created at runtime; never seeded or shared). See "Borderline
tables" under PMS-259 below.

lookup: `ticket_queues`, `ticket_statuses`, `ticket_priorities`, `ticket_types`,
`ticket_categories`, `ticket_automation_rules`, `work_types`, `time_rounding_rules`,
`task_statuses`, `sla_policies`, `sla_notifications`, `rate_cards`, `tax_rates`, `asset_types`,
`kb_categories`, `notification_channels`, `notification_templates`, `notification_rules`,
`user_notification_preferences` (user_id), `business_hours`, `holiday_calendars`,
`on_call_schedules`, `email_parse_rules`, `rmm_connections`, `rmm_alert_rules` (assign_to_id),
`appointment_reminders`, `tenant_settings`, `module_config`.

seq: `ticket_sequences`, `invoice_sequences`.

auth: `users`, `user_sessions` (user_id), `api_keys` (user_id), `password_reset_tokens`
(user_id), `tenant_invitations` (invited_by, accepted_by), `teams` (manager_id), `team_members`
(user_id).

## Decomposition (child issues of PMS-255) and where each piece landed

The nine steps below were the original dependency-ordered breakdown, each a runner-sized PR.
Each now names the artifact that carries it, so a reader can go read the code rather than the
plan. Status belongs in YouTrack, not here; follow the issue ids.

1. **GUC plumbing - route every PSA service query through `begin_with_tenant`.**
   `Database::begin_with_tenant` (`src/db/pool.rs`) opens the transaction and sets
   `app.current_tenant`. `scripts/check-pool-safety.nu` is the standing gate: a serving
   `.pool()` call needs an adjacent `// SAFETY (PMS-285` note saying why it legitimately
   skips the GUC. PMS-256 / PMS-285 / PMS-692 lineage.
2. **Flip RLS fail-closed + add `WITH CHECK` + `BYPASSRLS` migration role.**
   `migrations/038_rls_fail_closed.sql` (PMS-257) for the policy;
   `migrations/094_rls_quotes_backstop.sql` and `095_rls_deferred_tables.sql` (PMS-683) for
   the tables added after the `038` loop ran. The role split is `Database`'s two pools, and
   the roles themselves are a deployment step (`docs/postgres-security.md`), because roles are
   cluster-global and a migration cannot safely create them.
3. **Cover the no-`tenant_id` tables.** `migrations/041_rls_cover_tenantless_tables.sql`
   (PMS-258) and `migrations/128_rls_tenantless_child_tables.sql` (PMS-874), which also added
   the sweep that makes the next such table fail a test rather than be found by audit; see the
   table above.
4. **Per-user lookup seeding + system-shared class (PMS-259).** `TenantService::copy_default_config`
   (`src/modules/tenants/service.rs`) and `migrations/039_system_shared_class.sql`. Detailed in
   the two sections below.
5. **Fix known cross-tenant leak points (PMS-260).** `AuthService::get_user_sessions` and
   `AuthService::logout_all` take a `tenant_id` and run under the GUC.
   `AuthService::find_user_placement` still reads `users` across tenants by design (it resolves
   which tenant a `sub` belongs to, before any session exists) and runs on the migrator pool;
   `routes_do_not_reach_global_login_helpers` in `tests/auth.rs` pins that no `routes.rs`
   reaches it. `InvitationsService::newest_pending_for` is the other deliberate pre-auth
   cross-tenant bridge, on the migrator pool and pinned by the same test.
   `TenantService::list_tenants` enumerates the RLS-exempt `tenants` root on the migrator pool
   and is gated on `super_admin` at the route. All three carry their `// SAFETY (PMS-285` note.
6. **Audit background workers + `from_trusted` escape hatches (PMS-261).** The workers
   enumerate tenants on the migrator pool, then bridge each unit of work through
   `TenantId::from_trusted`; `src/modules/audit/context.rs` documents that seam.
   `tests/worker_tenant_isolation.rs` pins that a worker's per-tenant unit of work neither
   reads nor writes another tenant's rows.
7. **Remove/redefine the `single-tenant` cargo feature + default-tenant landing audit.** The
   feature is gone (PMS-262): `Cargo.toml` declares only `multi-tenant` and `server`, and
   `AppConfig::is_multi_tenant` (`src/main.rs`) returns `true` unconditionally. The default
   tenant id is resolved in two places, neither of them under `src/db/` (which holds only
   `mod.rs`, `pool.rs` and `provision.rs`): `parse_seed_source_tenant_id` in
   `src/modules/tenants/service.rs` reads `MOKOSH_SEED_TENANT_ID` and falls back to
   `Uuid::from_u128(1)`, and
   `default_bunyip_tenant_id` in `src/modules/auth/middleware.rs` reads
   `OIDC_DEFAULT_TENANT_ID` with the same fallback. `is_stuck_in_default` next to it is what
   moves a normal user off that tenant.
8. **Backfill migration + verification query** for existing co-mingled default-tenant rows.
   Resolved: no production data exists (the DB is wiped before go-live), so the backfill is a
   no-op; `migrations/040_backfill_comingled_default_tenant.sql` records that and asserts the
   zero-co-mingling invariant fail-loud. See the resolved decision below.
9. **Per-user isolation integration test suite (PMS-264).** `tests/per_user_isolation.rs`:
   two users in two personal tenants, driven through the real HTTP API, asserting cross-user
   read and write denial per module. The DB-engine face of the same guarantee (a write whose
   `tenant_id` differs from the GUC is rejected with SQLSTATE `42501`) is in
   `tests/rls_isolation.rs`.

## Editable-lookup seeding (PMS-259)

These tables are **editable-lookup** and are seeded per tenant by
`TenantService::copy_default_config` (src/modules/tenants/service.rs), copying the
migration-`023` default-tenant rows and re-scoping them to the new tenant. Inter-lookup
foreign keys are re-linked to the new tenant's freshly copied rows by name.

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
| `notification_templates` (worker + auth subset) | yes | - |
| `notification_rules` (worker + auth subset) | yes | `template_id` by (event, channel) |

The notification subset is the three worker events (`appointment.reminder`, `sla.at_risk`,
`sla.breached`) plus the two transactional auth events (`auth.password_reset`, `auth.welcome`).
The auth pair was added by PMS-700: the dispatcher is their only delivery path now that the
duplicate hard-coded bodies are gone from `Mailer`, so a tenant without those rows would get no
password-reset or welcome mail. Migration `097` backfills the same pair into older tenants.

The seed is **idempotent**: `copy_default_config` skips entirely when the tenant already holds
`ticket_statuses` rows, and runs in a single transaction so a tenant is either fully seeded or
not at all. A retried provisioning never double-seeds.

### Borderline tables (confirmed classification)

These resolve the "Lookup classification" open decision for PMS-255.4:

- `business_hours` - **editable-lookup**. Despite feeling like infrastructure it is per-tenant,
  user-editable (timezone, weekly schedule), and seeded. A future global maintenance-window
  calendar would be a separate system-shared table, not this one.
- `payment_gateway_configs` - **business**, NOT a lookup. It holds per-tenant secrets (encrypted
  with `ENCRYPTION_KEY`); it is created by the user when they connect a gateway and must never be
  seeded or shared. Stays isolated.
- `email_mailboxes` - **business**, NOT a lookup. Per-tenant credentials / connection settings
  created at runtime; not seeded, not shared.

## System-shared class (PMS-259, structural)

Reserved for future non-editable global rows (e.g. system statuses, maintenance windows).
Implemented by `migrations/039_system_shared_class.sql` and amended by
`migrations/127_system_shared_policy_on_optin.sql` (PMS-875). **No table opts in yet and no
system-shared row exists**; every lookup `tenant_id` column is still `NOT NULL`, so the
mechanism is a no-op for current data.

Mechanism:

1. **Sentinel**: `tenant_id IS NULL` means "global / system-shared".
2. **Read (RLS)**: the `tenant_isolation` policy on a member table reads
   `tenant_id IS NULL OR tenant_id = <current-tenant match>`, so a global row is visible to
   every tenant. (PMS-257 owns the fail-closed tenant match and the WITH CHECK; the `IS NULL`
   read clause is owned here.) `039` applied that shape with a one-shot loop over the tables
   that existed when it ran, which left every table created since (`094`, `095`, `105`, and
   every new-table migration, which copies the plain `038` block) carrying no `IS NULL`
   disjunct: opting one of them in would have stored global rows no tenant could read.
   PMS-875 moved the read half into the opt-in function itself, so the disjunct is attached
   when a table joins the class rather than depending on when the table was created. Tables
   that never join keep the plain `038` policy, which is correct for them.
3. **Write guard (DB)**: trigger function `mokosh_guard_system_shared_row()` rejects any
   INSERT / UPDATE / DELETE touching a `tenant_id IS NULL` row unless the session sets
   `app.allow_system_writes = 'on'` (reserved for the migration / super-admin role). Raises
   SQLSTATE `42501` (`insufficient_privilege`).
4. **Write guard (app)**: application code must never write a system-shared row from an ordinary
   request path. Only an explicit super-admin / migration path sets `app.allow_system_writes`
   and writes globals. Ordinary lookup CRUD always writes `tenant_id = <caller tenant>`, so it
   can never produce a global row.
5. **Opt-in**: a table joins the class later with
   `SELECT mokosh_enable_system_shared('<table>');` which drops the `tenant_id` NOT NULL
   constraint, recreates `tenant_isolation` in the disjunct read form above (with the
   WITH CHECK left non-disjunct, so an ordinary session still cannot write a global row), and
   attaches the `guard_system_shared_row` trigger. It raises `undefined_column` (42703) before
   touching anything if the target has no `tenant_id` column, which is what the `041`
   parent-join tables get. The global rows are then inserted from a privileged
   (`app.allow_system_writes = 'on'`) session. `tests/system_shared_class.rs` proves both
   halves on `saved_dashboards`, a table created long after `039` ran.

This keeps genuinely global config from being needlessly duplicated per tenant while preserving
strict per-user isolation for everything editable.

## Open decisions to confirm (do not block the analysis, but resolve before the affected issue)

- ~~**Legacy co-mingled data ownership (PMS-255.8).**~~ Resolved with the product owner
  (2026-06-13): Mokosh is not in production and the database is wiped before go-live, so there is
  no legacy co-mingled business data to re-home or quarantine. The backfill
  (`migrations/040_backfill_comingled_default_tenant.sql`) is intentionally a no-op; it instead
  asserts the end-state invariant fail-loud (no business row sits in the default tenant
  `00000000-0000-0000-0000-000000000001`; lookup/auth/seq rows are excluded). The standalone
  verification query is `docs/dev-docs/pms-263-verify-no-comingled-business-rows.sql`. This also
  sidesteps the unsafe one-shot path: personal tenants are provisioned lazily on login
  (PMS-243/245), so a bulk SQL backfill would have no tenant to resolve most owners to.
- **Portal identity (PMS-255.6).** Portal runs on a `contacts`-row identity (`CurrentContact`,
  company-scoped), a separate plane from `users`, with its own `portal_auth_middleware` and
  `RequirePortalAuth` extractor (`src/modules/portal/middleware.rs`, joined by
  `RequirePortalBillingContact` in PMS-993, which adds the billing-contact role check on top of
  it for the invoice routes) and its own credential
  lifecycle under `/api/v1/portal/auth/*` (PMS-820). Per-user isolation is deliberately NOT
  applied to portal contacts: the plane stays company-scoped and is revisited with the orgs
  work. `PortalService::login` is a pre-auth `(tenant_slug, email)` resolve on the migrator
  pool with the `// SAFETY (PMS-285` note pointing back at this section; keep the two in step
  if the decision changes.
- ~~**Lookup classification.**~~ Resolved by PMS-259: see "Borderline tables (confirmed
  classification)" above. `business_hours` is editable-lookup; `payment_gateway_configs` and
  `email_mailboxes` are business.
