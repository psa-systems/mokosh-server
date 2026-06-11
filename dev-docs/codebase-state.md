# Codebase state - mokosh-server

A practical reference for what's actually implemented in this repo.
Derived from a 2026-05-06 audit and intended to be kept current
alongside source changes.

> **Update 2026-06-03 (Service Desk slice).** The metrics and
> per-module table below predate substantial work and are stale in
> places. Confirmed changes since the audit: **F3 (ticket DTO joins)
> is done** - `tickets/service.rs` builds `TicketResponse` from a
> JOINed query (`TICKET_RESPONSE_SELECT`), no `String::new()`
> placeholders remain. **F8 (time tracking) is done and then some** -
> `time_tracking` is a real, router-mounted module (work types, time
> entries, timesheets, timers, rounding rules) with rounding actually
> applied, work-type rate derivation, a manager approve/reject state
> machine, write-side tenant validation, and integration coverage in
> `tests/time_tracking.rs`. Treat the `time_tracking` row in the
> placeholder table and the F3/F8 entries under "Proposed fixes" as
> closed. A broader re-audit of the other formerly-placeholder
> modules (many are now `merge`d in `api/router.rs`) is still
> outstanding.

## At a glance

| Metric | Value |
| --- | --- |
| Total Rust LOC under [`src/`](../src/) (excluding modules) | ~3,000 |
| LOC under [`src/modules/`](../src/modules/) | ~6,950 |
| Modules implemented | **4 / 18** (`auth`, `contacts`, `tenants`, `tickets`) |
| Module placeholders | **14** |
| Route groups under `/api/v1` | **25 nested + `/health`** |
| Route groups returning real data | **4** |
| Route groups returning HTTP 501 | **22** (includes all `/api/v1/portal/*`) |
| Schema tables in [`migrations/001_initial_schema.sql`](../migrations/001_initial_schema.sql) | **71** |
| Tests | **0** |
| TODOs in source | **11** |

The schema is far ahead of the handler layer. Most "missing" features
already have tables waiting in the initial migration; the gap is
service + route code, not data modeling.

## Architecture

```
HTTP request
   |
   v
TraceLayer + Compression + CORS (any/any/any)         <- src/api/router.rs:106-113
   |
   v
auth_middleware (decode JWT -> AuthState)             <- src/modules/auth/middleware.rs
   |
   v
nested router for /api/v1/<group>                     <- src/api/router.rs:35-99
   |
   v
RequireAuth / RequireRole extractor pulls CurrentUser
   |
   v
Service method (always takes tenant_id: Uuid)         <- src/modules/<module>/service.rs
   |
   v
sqlx query against PostgreSQL
```

Notable layer details:

- **Auth middleware always runs** (even for unauthenticated routes
  like `/auth/login`). It sets an `AuthState::default()` for missing
  / invalid tokens; route handlers opt into auth via the
  `RequireAuth` extractor.
- **Multi-tenancy is enforced ad-hoc.** Every service method accepts
  `tenant_id: Uuid`; there is no middleware-level scoping. A new
  handler that forgets to pass `user.tenant_id` becomes a
  cross-tenant data leak. See
  [Cross-cutting issues](#cross-cutting-issues) #8.
- **Tenant feature flag** (`multi-tenant` / `single-tenant`,
  default `multi-tenant`) is currently inert at the routing layer:
  the same routes are exposed in either mode.

## Per-module status

### Implemented modules

#### `auth` (~1,700 LOC)

Files: [`routes.rs`](../src/modules/auth/routes.rs) (302),
[`service.rs`](../src/modules/auth/service.rs) (706),
[`models.rs`](../src/modules/auth/models.rs) (627),
[`middleware.rs`](../src/modules/auth/middleware.rs) (198),
[`bootstrap.rs`](../src/modules/auth/bootstrap.rs) (123).

**Endpoints:** 14 total.

| Path | Method | Auth | Notes |
| --- | --- | --- | --- |
| `/api/v1/auth/login` | POST | public | No rate limit; see F2 |
| `/api/v1/auth/logout` | POST | required | |
| `/api/v1/auth/refresh` | POST | public | (uses refresh token) |
| `/api/v1/auth/forgot-password` | POST | public | Email not actually sent (TODO) |
| `/api/v1/auth/reset-password` | POST | public | |
| `/api/v1/auth/me` | GET / PUT | required | Sanitizes role/status on PUT |
| `/api/v1/auth/me/password` | PUT | required | |
| `/api/v1/auth/me/sessions` | GET | required | |
| `/api/v1/auth/me/sessions/:session_id` | DELETE | required | |
| `/api/v1/auth/users` | GET | admin/manager | **Returns empty list (F1)** |
| `/api/v1/auth/users` | POST | admin | |
| `/api/v1/auth/users/:user_id` | GET / PUT | admin | |

Tech: Argon2 (via [`utils/crypto.rs`](../src/utils/crypto.rs)) for
password hashing, JWT HS256 (via `jsonwebtoken`) for access + refresh
tokens, sessions persisted in the `user_sessions` table.

**Open TODOs:**

- [`service.rs:81`](../src/modules/auth/service.rs#L81) - MFA TOTP
  verify not implemented; users with `mfa_enabled = true` can be
  blocked from logging in entirely.
- [`service.rs:196`](../src/modules/auth/service.rs#L196) - password
  reset token is persisted but no email is sent. The user has no way
  to learn the token.
- [`service.rs:345`](../src/modules/auth/service.rs#L345) - welcome
  email for newly created users is not sent.
- [`routes.rs:238`](../src/modules/auth/routes.rs#L238) - `list_users`
  hard-codes an empty `PaginatedResponse`. The endpoint advertises
  listing but does not list. Tracked as **F1**.

**Schema touched:** `users`, `user_sessions`, `api_keys` (defined
but no handler), `password_reset_tokens`, `tenants` (read).

#### `tickets` (~2,400 LOC)

Files: [`routes.rs`](../src/modules/tickets/routes.rs) (401),
[`service.rs`](../src/modules/tickets/service.rs) (888),
[`models.rs`](../src/modules/tickets/models.rs) (733),
[`automation.rs`](../src/modules/tickets/automation.rs) (315).

**Endpoints:** 11 total.

| Path | Method | Notes |
| --- | --- | --- |
| `/api/v1/tickets` | GET / POST | List + create |
| `/api/v1/tickets/:ticket_id` | GET / PUT | |
| `/api/v1/tickets/:ticket_id/assign` | POST | |
| `/api/v1/tickets/:ticket_id/notes` | GET / POST | `add_note` does not send email even when requested (TODO) |
| `/api/v1/tickets/statuses` | GET | Lookup table |
| `/api/v1/tickets/priorities` | GET | Lookup table |
| `/api/v1/tickets/queues` | GET | Lookup table |
| `/api/v1/tickets/types` | GET | Lookup table |

All endpoints require auth.

**Critical defect: shallow response DTOs.** Every ticket-returning
handler builds `TicketResponse` with `name: String::new(), // Would
be joined from DB` for nine string fields:

- `status.name`, `status.color`
- `priority.name`, `priority.color`
- `type_name`, `category_name`, `queue_name`
- `company_name`, `contact_name`
- `assigned_to_name`, `created_by_name`

The endpoint returns `200 OK` but those fields come back empty. Any
client that depends on them (which is most of them, since the client
displays names not UUIDs) will render with blanks. See
[`routes.rs:71-99,128-159,178-209,231-262,287-318`](../src/modules/tickets/routes.rs#L71).
Tracked as **F3** - the highest-impact server fix.

**Open TODOs:**

- [`service.rs:132`](../src/modules/tickets/service.rs#L132) -
  `on_create` automation rules not invoked.
- [`service.rs:409`](../src/modules/tickets/service.rs#L409) -
  `on_update` automation rules not invoked.
- [`service.rs:477`](../src/modules/tickets/service.rs#L477) -
  `add_note` ignores `send_email: true`.
- [`automation.rs:235`](../src/modules/tickets/automation.rs#L235),
  [`automation.rs:243`](../src/modules/tickets/automation.rs#L243) -
  notification + webhook dispatch from rules unwired (gated on the
  `notifications` placeholder module).

**Schema touched:** `tickets`, `ticket_sequences`, `ticket_notes`,
`ticket_attachments`, `ticket_statuses`, `ticket_priorities`,
`ticket_queues`, `ticket_types`, `ticket_categories`,
`ticket_automation_rules`. Joins to `companies`, `contacts`, `users`.

#### `contacts` (~1,800 LOC)

Files: [`routes.rs`](../src/modules/contacts/routes.rs) (299),
[`service.rs`](../src/modules/contacts/service.rs) (845),
[`models.rs`](../src/modules/contacts/models.rs) (630).

**Endpoints:** 16 total. The router exposes companies, contacts, and
sites all under `/api/v1/contacts/...`. The empty
`.nest("/companies", Router::new())` declared at
[`router.rs:45`](../src/api/router.rs#L45) is dead - it matches
nothing, so `/api/v1/companies` returns 404 instead of an alias. See
[Cross-cutting issues](#cross-cutting-issues) #11.

| Path | Method |
| --- | --- |
| `/api/v1/contacts/companies` | GET / POST |
| `/api/v1/contacts/companies/:company_id` | GET / PUT / DELETE |
| `/api/v1/contacts/companies/:company_id/contacts` | GET |
| `/api/v1/contacts/companies/:company_id/sites` | GET |
| `/api/v1/contacts/contacts` | GET / POST |
| `/api/v1/contacts/contacts/:contact_id` | GET / PUT / DELETE |
| `/api/v1/contacts/sites` | POST |
| `/api/v1/contacts/sites/:site_id` | GET / PUT / DELETE |

**Defect: `update_site` is a silent no-op.**
[`routes.rs:273-288`](../src/modules/contacts/routes.rs#L273) accepts
the request body, validates it, then calls `get_site` and returns
the unmodified record. A `200 OK` disguises a missed write. Tracked
as **F4**.

**Open TODOs:**

- [`routes.rs:281`](../src/modules/contacts/routes.rs#L281) -
  `update_site` does not actually update.
- [`service.rs:332`](../src/modules/contacts/service.rs#L332) -
  `create_contact` ignores `create_portal_access: true`.

**Schema touched:** `companies`, `contacts`, `sites`.

#### `tenants` (~810 LOC)

Files: [`routes.rs`](../src/modules/tenants/routes.rs) (171),
[`service.rs`](../src/modules/tenants/service.rs) (475),
[`models.rs`](../src/modules/tenants/models.rs) (149).

**Endpoints:** 7 total. All require auth; create / suspend /
activate are super-admin only.

| Path | Method | Authz |
| --- | --- | --- |
| `/api/v1/tenants` | GET | super_admin |
| `/api/v1/tenants` | POST | super_admin |
| `/api/v1/tenants/:tenant_id` | GET | super_admin or own tenant |
| `/api/v1/tenants/:tenant_id` | PUT | super_admin or admin of that tenant |
| `/api/v1/tenants/:tenant_id/suspend` | POST | super_admin |
| `/api/v1/tenants/:tenant_id/activate` | POST | super_admin |
| `/api/v1/tenants/:tenant_id/usage` | GET | super_admin or own tenant |

**No in-source TODOs.** The service additionally exports
`get_module_config` and `update_module_config` against the
`tenant_settings` and `module_config` tables, but no route maps to
them. Tracked as **F5**.

**Schema touched:** `tenants`, `tenant_settings`, `module_config`,
plus reads across `users`, `tickets`, etc. for usage.

#### `seed` (PMS-157, no routes)

Files: [`service.rs`](../src/modules/seed/service.rs),
[`middleware.rs`](../src/modules/seed/middleware.rs),
[`data.rs`](../src/modules/seed/data.rs).

First-visit demo-data seeding. A middleware (`seed_middleware`) runs
inner of the auth middleware so `AuthState` is populated, and on the
first authenticated visit by a tenant it spawns `SeedService::ensure_demo_seeded`
detached (never adds latency, all errors logged and swallowed). The
seed inserts one demo company, two contacts, and three tickets through
the real `ContactService` / `TicketService` create paths. Idempotency:
an in-process seen-set, an atomic compare-and-set on
`tenants.settings->>'demo_seeded'`, and an emptiness check that skips
tenants that already have companies (so established tenants are never
polluted on the first visit after a deploy). Disable with
`MOKOSH_DEMO_SEED=false` (e.g. E2E/staging on the shared default
tenant).

**Schema touched:** `tenants` (the `demo_seeded` settings flag), plus
inserts into `companies`, `contacts`, `tickets`.

### Placeholder modules (14)

Each is a single-line `mod.rs` (`//! <name> module placeholder`) and
the router maps each to `stub_routes()` which returns
`HTTP 501 Not implemented yet`. Schema tables exist for every one of
these, so adding a real module is mostly handler + service work
against an existing schema.

| Module | Schema tables in [`001_initial_schema.sql`](../migrations/001_initial_schema.sql) | Client UI surface affected |
| --- | --- | --- |
| `assets` | `asset_types`, `assets`, `asset_relationships`, `configuration_items`, `credential_vault`, `asset_audit_log` | `/assets`, `/assets/new`, `/assets/:id` |
| `audit` | `audit_log` | none direct |
| `billing` | `invoices`, `invoice_sequences`, `invoice_lines`, `payments`, `payment_gateway_configs`, `tax_rates` | `/invoices`, `/invoices/new`, `/invoices/:id`, `/payments` |
| `calendar` | `appointments`, `user_availability`, `time_off`, `on_call_schedules` | `/calendar`, `/dispatch` |
| `contracts` | `contracts`, `contract_items`, `contract_hour_balances`, `rate_cards`, `rate_card_items` | `/contracts`, `/contracts/new`, `/contracts/:id` |
| `knowledge_base` | `kb_categories`, `kb_articles`, `kb_article_versions` | `/kb`, `/kb/articles`, `/portal/kb` |
| `notifications` | `notification_channels`, `notification_templates`, `user_notification_preferences`, `notifications`, `notification_rules` | notification bell + `/settings/notifications` |
| `portal` | (uses `contacts` for portal identity) | all `/portal/*` (7 routes) |
| `projects` | `projects`, `project_phases`, `task_statuses`, `tasks`, `task_dependencies` | `/projects`, `/projects/new`, `/projects/:id`, `/projects/:id/tasks` |
| `reports` | (aggregate over many tables) | `/reports`, `/reports/:report_type` |
| `rmm` | `rmm_connections`, `rmm_device_mappings`, `rmm_alert_rules` | `/settings/integrations` |
| `settings` | `tenant_settings`, `module_config` | `/settings/*` |
| `sla` | `sla_policies`, `sla_targets`, `business_hours`, `holiday_calendars` | indirect (SLA fields on tickets) |
| ~~`time_tracking`~~ **(now implemented, see Update 2026-06-03)** | `work_types`, `time_entries`, `time_rounding_rules`, `active_timers` | `/time`, `/time/new`, `/timesheets` |

47 of the 71 schema tables are reachable only by future placeholder
implementations.

## Cross-cutting issues

These appear across implemented modules and are best fixed once at
the infrastructure or shared-helper layer.

1. **Shallow ticket DTOs.** See `tickets` module above. Highest-
   impact server defect.
2. **Portal endpoints all return 501.** [`router.rs:90-99`](../src/api/router.rs#L90).
   The client portal renders pages that cannot ever fetch data.
3. **No tests.** No `tests/` dir, no `*test*.rs` files, no
   integration coverage for any route group.
4. **Tracing is structural, not semantic.** `TraceLayer` is wired
   globally; `RUST_LOG` is honored. Service methods do not open
   named spans, so request-scoped diagnostics through the body of a
   transaction are impossible.
5. **No rate limit on `/auth/login`** (or anywhere). The `governor`
   crate is in [`Cargo.toml:85`](../Cargo.toml#L85) but never
   imported. Tracked as **F2**.
6. **CORS = Any / Any / Any.** [`router.rs:108-113`](../src/api/router.rs#L108).
   Dev-friendly. Must tighten before any non-local environment.
   Tracked as **F13**.
7. **`utils/pagination.rs` exists but is bypassed.** `auth::list_users`
   constructs a `PaginatedResponse` of `vec![]`; `tenants` and
   `contacts` build inline pagination SQL.
8. **Multi-tenancy: typed scoping rollout in progress (PMS-139).** The
   foundation has landed: a `TenantId` newtype
   ([`auth/tenant.rs`](../src/modules/auth/tenant.rs)) whose only in-crate
   constructor is `pub(crate)` and is reached solely via
   `CurrentUser::tenant()` (the `TenantScoped` trait), so a `TenantId` always
   traces back to an authenticated claim. Service methods that take
   `tenant_id: TenantId` can no longer be called with a bare `Uuid` (pinned by
   a `compile_fail` doctest on `TenantId`). **Migrated so far:** `reports` (the
   reference pattern - handlers use `u.tenant()`, service + `custom::run` take
   `TenantId`), `rmm`, `time_tracking`, `assets`, `projects`, `calendar`, `sla`,
   and `contracts`. The RMM ingest webhook is
   unauthenticated (machine HMAC), so it uses the `from_trusted` escape hatch
   with a `// SAFETY:` comment. Where a migrated module calls a not-yet-swept
   hub (`audit_write`, `notifications::dispatch`, `TicketService`) it unwraps
   with `tenant_id.get()` transitionally; those hubs migrate last. Cross-tenant
   workers (calendar reminder, sla sweep, contract lifecycle) read tenant ids
   straight off DB-projected rows as `Uuid` and dispatch through the hubs, so
   they are untouched by the sweep.
   **Remaining:** sweep the other ~9 modules' `routes.rs` + `service.rs` the
   same way (PMS-139 follow-ups). Until the sweep completes this item stays
   open.
9. **`validator::Validate` coverage is uneven.** `Create*Request`
   and `Update*Request` types are validated. `*Filter` query types
   (`TicketFilter`, `CompanyFilter`, `ContactFilter`) are not.
   Tracked as **F9**.
10. **Single 1688-line initial migration.** Adding any feature
    module on the server side will need to touch
    [`001_initial_schema.sql`](../migrations/001_initial_schema.sql)
    plus the seed file. Pre-prod is the cheapest moment to split it
    per feature. Tracked as **F14**.
11. **Companies route alias is dead.**
    [`router.rs:45`](../src/api/router.rs#L45) declares
    `.nest("/companies", Router::new())` with the comment "Alias
    handled by contact routes". The alias is empty: it matches
    nothing. `/api/v1/companies` returns 404, not the intended
    alias. Companies are reachable only at
    `/api/v1/contacts/companies`.
12. **Cross-repo: client and server share DTOs by byte-identical
    copy-paste.** All `.rs` files in
    [`src/modules/{auth,contacts,tenants,tickets}/`](../src/modules/)
    diff cleanly to zero against
    [`mokosh-clients/src/modules/...`](../../mokosh-clients/src/modules/).
    Each `mod.rs` uses `#[cfg(feature = "server")]` to omit handler
    and service code from the WASM build. Currently in lock-step;
    vulnerable to silent drift the moment one side is edited
    without porting. See
    [`client-server-integration.md`](client-server-integration.md#dto-sharing).

## Proposed fixes

Concrete, scoped patches. IDs are referenced from per-module
sections above and from
[`client-server-integration.md`](client-server-integration.md).

### F1. `auth/routes.rs::list_users` - implement instead of returning empty

Today ([`routes.rs:228-246`](../src/modules/auth/routes.rs#L228)):

```rust
async fn list_users(...) -> AppResult<Json<PaginatedResponse<UserResponse>>> {
    if !user.role.is_admin() && !matches!(user.role, super::UserRole::Manager) {
        return Err(AppError::Forbidden(...));
    }
    // TODO: Implement proper pagination query
    Ok(Json(PaginatedResponse::new(vec![], pagination.page, pagination.per_page(), 0)))
}
```

Replace with a real query against `users` for `tenant_id =
user.tenant_id`, paginated via [`utils/pagination.rs`](../src/utils/pagination.rs).
Pattern already exists in
[`tenant_service::list_tenants`](../src/modules/tenants/service.rs#L133).

### F2. Rate-limit `/api/v1/auth/login`

`governor` is in deps but unused. Add a `tower::Layer` keyed on
`(ConnectInfo<SocketAddr>.ip(), email)` with a quota of ~5/minute,
applied only to `/login` inside `auth_routes()`.

### F3. Fill ticket DTOs from JOINed query - **DONE (2026-06-03)**

Implemented: `tickets/service.rs` selects via `TICKET_RESPONSE_SELECT`
(joins statuses, priorities, queues, types, categories, companies,
contacts, and both user roles) and builds `TicketResponse` from the
joined row. No `String::new()` placeholders remain. Original note kept
below for history.

Highest-impact fix. Patch
[`tickets/service.rs::list_tickets`](../src/modules/tickets/service.rs#L194)
(and `get_ticket`, `update_ticket`, `assign_ticket`) so the SELECT
joins `ticket_statuses`, `ticket_priorities`, `ticket_queues`,
`ticket_types`, `ticket_categories`, `companies`, `contacts`, and
`users` (assigned_to + created_by). Build `TicketResponse` from the
joined row in the service, not the route handler. Today the route
handler builds the DTO with `String::new()` for every joined name
([`routes.rs:71-99,128-159,178-209,231-262,287-318`](../src/modules/tickets/routes.rs#L71)).

### F4. `contacts/routes.rs::update_site` - actually call update

Today ([`routes.rs:273-288`](../src/modules/contacts/routes.rs#L273)):

```rust
async fn update_site(...) -> AppResult<Json<SiteResponse>> {
    request.validate()?;
    // TODO: Implement update_site in service
    let site = state.contact_service.get_site(user.tenant_id, site_id).await?;
    Ok(Json(site.into()))
}
```

Add `update_site(&self, tenant_id, site_id, &UpdateSiteRequest) ->
AppResult<Site>` to
[`contact_service`](../src/modules/contacts/service.rs) (mirror
`update_company` at
[`service.rs:207`](../src/modules/contacts/service.rs#L207)), then
have the route call it.

### F5. Expose `tenant_service::{get,update}_module_config` over HTTP

[`tenants/service.rs:283-460`](../src/modules/tenants/service.rs#L283)
defines module-config helpers that read/write `tenant_settings` and
`module_config`. No route maps to them. Add:

- `GET  /api/v1/tenants/:tenant_id/modules/:module`
- `PUT  /api/v1/tenants/:tenant_id/modules/:module`

This unblocks the client's `/settings/integrations` page.

### F6. Wire `/api/v1/portal/*` to a contact-scoped session

Portal endpoints all 501 ([`router.rs:90-99`](../src/api/router.rs#L90)).
Portal users are `Contact` rows (the schema has
`contacts.has_portal_access`), not `User` rows. Implement:

- `POST /api/v1/portal/auth/login` - look up `Contact` by email,
  verify password (new `contact.password_hash` column or piggyback on
  a `portal_users` table).
- `POST /api/v1/portal/tickets` - create ticket scoped to
  `contact.company_id`, internal flag = false.
- `GET  /api/v1/portal/tickets` - list tickets where `contact_id =
  current_contact_id`.
- `GET  /api/v1/portal/invoices` - blocked on F7.
- `GET  /api/v1/portal/kb` - blocked on the `knowledge_base`
  module.

This is the only change that unblocks the client portal, which
already ships rendered pages.

### F7. Stand up minimal read-only `/api/v1/invoices`

Tables already exist. Create
[`src/modules/billing/`](../src/modules/billing/) with at minimum:

- `GET /api/v1/invoices` (paginated, filter by `company_id`, `status`)
- `GET /api/v1/invoices/:id`

Postpone POST/PUT.

### F8. Stand up `/api/v1/time-entries` + `/api/v1/timesheets` - **DONE (2026-06-03)**

Delivered well past the original read-only scope. `time_tracking` is a
real module mounted in `api/router.rs`, with CRUD for work types, time
entries, timers, and rounding rules, plus timesheet aggregation. The
Service Desk slice added on top:

- **Rounding actually applied.** `apply_rounding` (floor to
  `minimum_minutes`, then round to `increment_minutes`; exact midpoint
  rounds up) runs on both `create_time_entry` and `stop_timer`, loading
  the tenant default rule. Billing-critical ordering is documented on
  the function.
- **Rate derived from work type.** `resolve_billing` precedence:
  explicit request rate > `work_type.default_rate` > none. `stop_timer`
  now prices the entry instead of inserting NULL rate/total with a
  hardcoded `is_billable = TRUE`.
- **Approval state machine.** `POST /timesheets/:user/:week/{approve,reject}`
  (manager+), transitioning `approval_status`; `TimesheetSummaryResponse`
  carries a week-level `approval_status` rollup. Submit on an empty week
  returns a zeroed summary rather than 404.
- **Write-side tenant validation.** `create_time_entry` / `start_timer`
  verify work-type/ticket/company belong to the tenant (FKs check
  existence, not ownership); `stop_timer`'s company-inference query is
  tenant-scoped; the single-active-timer race maps to `Conflict`.
- **Tests.** `tests/time_tracking.rs` drives the two-actor happy path
  (technician times + submits, manager approves) plus a technician
  cannot-approve guard; `apply_rounding` / `resolve_billing` have
  pure-fn unit tests.

DTOs were ported to `mokosh-clients`/`mokosh-apps` byte-identical (5th
shared module; `rust_decimal` added to the client with `db-postgres`
omitted). Original note kept below for history.

Same shape as F7, against `time_entries`, `active_timers`,
`time_rounding_rules`, `work_types`. Highest-leverage of the 14
placeholder modules - the client's `/time` page is one of the most
used surfaces and the data is user-produced.

### F9. Add `validator::Validate` to `*Filter` query types

`TicketFilter` ([`tickets/models.rs:446`](../src/modules/tickets/models.rs#L446)),
`CompanyFilter` and `ContactFilter`
([`contacts/models.rs:613,623`](../src/modules/contacts/models.rs#L613))
are deserialized from the query string and passed to SQL as-is. Add
`#[derive(Validate)]` plus length/regex constraints, then call
`filter.validate()?` at the top of each list handler.

### F10. Add module-level integration tests

Stand up `tests/` with one `#[tokio::test]` per real route group:
auth happy-path login + me, contacts CRUD, tenants list (super_admin),
tickets create/list/get/update + add note. `testcontainers`-backed
Postgres is cleanest, but the dev compose
`host.docker.internal` already gives a real DB.

### F11. Wire automation triggers (depends on `notifications`)

Once `notifications` becomes a real module, have the ticket service
call `AutomationEngine::process_rules` on `on_create` and `on_update`
([`tickets/service.rs:132,409`](../src/modules/tickets/service.rs#L132)
and [`automation.rs:235,243`](../src/modules/tickets/automation.rs#L235)).
Gated on F12.

### F12. Skeletons for the remaining placeholder modules

Lowest-priority, but to keep the placeholder list from growing:
generate a `routes.rs` per module with handlers that respond with
self-documenting 501 bodies (current generic body is just "Not
implemented yet").

### F13. Tighten CORS

[`router.rs:108-113`](../src/api/router.rs#L108). Replace
`Any/Any/Any` with origins from `MOKOSH_ALLOWED_ORIGINS` env var,
methods restricted to `GET/POST/PUT/DELETE`, and headers restricted
to `Authorization`, `Content-Type`, `Accept`.

### F14. Split the 1688-line initial migration

Suggested split (one `.sql` per): `002_auth.sql`,
`003_tenants.sql`, `004_contacts.sql`, `005_tickets.sql`,
`006_time_tracking.sql`, `007_projects.sql`, `008_calendar.sql`,
`009_contracts.sql`, `010_billing.sql`, `011_assets.sql`,
`012_knowledge_base.sql`, `013_notifications.sql`, `014_rmm.sql`,
`015_audit.sql`, `016_files.sql`, `017_settings.sql`. Move
`002_seed_data.sql` last and renumber. Each future feature module
adds its own migration without touching others.

## Priority

| Priority | Items |
| --- | --- |
| **P0** | F6 (portal 501), F2 (login rate limit) |
| **P1** | F3 (ticket DTO joins), F1 (`list_users` returns empty), F4 (`update_site` no-op), F7 (billing module), F8 (time tracking module) |
| **P2** | F10 (tests), F9 (filter validation), F5 (module config endpoints), F11 (automation, gated on F12) |
| **P3** | F13 (CORS hardening), F14 (migration split), F12 (placeholder skeletons) |

## Verifying the API locally

When the dev stack is up (see [README.md](../README.md) -
"Quick start"):

```nu
# Health
http get http://($env.MOKOSH_HOST_BIND_IP):($env.MOKOSH_PORT)/api/v1/health

# Login (seed admin)
let login = (
    http post http://($env.MOKOSH_HOST_BIND_IP):($env.MOKOSH_PORT)/api/v1/auth/login {
        email: "admin@example.com",
        password: "devpassword12",
    }
)
let auth = [Authorization $"Bearer ($login.access_token)"]

# One read per real route group
http get --headers $auth http://($env.MOKOSH_HOST_BIND_IP):($env.MOKOSH_PORT)/api/v1/auth/me
http get --headers $auth http://($env.MOKOSH_HOST_BIND_IP):($env.MOKOSH_PORT)/api/v1/tickets
http get --headers $auth http://($env.MOKOSH_HOST_BIND_IP):($env.MOKOSH_PORT)/api/v1/contacts/companies
http get --headers $auth http://($env.MOKOSH_HOST_BIND_IP):($env.MOKOSH_PORT)/api/v1/tenants

# Confirm a stub group returns 501
http get --headers $auth --full http://($env.MOKOSH_HOST_BIND_IP):($env.MOKOSH_PORT)/api/v1/invoices
```

Three things this surfaces directly:

1. `tickets` list comes back with empty `status.name`,
   `priority.name`, `company_name` etc. (validates F3).
2. `/api/v1/companies` (without the `/contacts/` prefix) returns 404
   (validates Cross-cutting #11).
3. Every stub group returns 501 with the body `Not implemented yet`
   (validates Cross-cutting #2).
