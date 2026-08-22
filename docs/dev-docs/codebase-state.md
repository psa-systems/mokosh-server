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

> **Update 2026-07-24 (module-status correction, PMS-684).** The
> "only `auth`/`contacts`/`tenants`/`tickets` have real handlers, most
> route groups return HTTP 501" framing is obsolete. `api/router.rs`
> now nests/merges ~30 implemented modules (billing, projects,
> calendar, contracts, quotes, assets, rmm, sla, saved_reports,
> workflows, time_tracking, dashboards, email_intake, approvals,
> settings, audit, data_transfer, and more) and the 501 placeholder
> router is gone. The "At a glance" and "Placeholder modules" tables
> below are kept for history but no longer reflect the handler layer.

> **Update 2026-08-22 (export-format status, PMS-854).** An earlier
> revision of this file said the PDF format of the report-export
> route was the sole remaining HTTP 501. It never returned 501:
> `export_report` in `reports/routes.rs` rejects every format other
> than `csv` with `AppError::BadRequest`, a 400. That is the intended
> contract, because one branch serves every unsupported value and
> `format` is an enumerated query parameter, so a value outside the
> implemented set is an out-of-range request rather than a
> server-side gap. Adding PDF is tracked in PMS-876. The remaining
> 501 references below all describe the retired placeholder router
> and are historical.

## At a glance

| Metric | Value |
| --- | --- |
| Total Rust LOC under [`src/`](../src/) (excluding modules) | ~3,000 |
| LOC under [`src/modules/`](../src/modules/) | ~6,950 |
| Modules implemented | **most** (~30 nested/merged in [`api/router.rs`](../src/api/router.rs); see the 2026-07-24 correction) |
| Module placeholders | **0** (the 501 placeholder router is gone) |
| Route groups under `/api/v1` | **~30 + `/health`** |
| Route groups returning real data | **most** |
| Report export formats | **CSV** ([`reports/routes.rs`](../src/modules/reports/routes.rs)); any other `format`, `pdf` included, is a 400 (see the 2026-08-22 correction) |
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
Service method (takes tenant_id: TenantId, PMS-139)   <- src/modules/<module>/service.rs
   |
   v
sqlx query against PostgreSQL
```

Notable layer details:

- **Auth middleware always runs** (even for unauthenticated routes
  like `/auth/login`). It sets an `AuthState::default()` for missing
  / invalid tokens; route handlers opt into auth via the
  `RequireAuth` extractor.
- **Multi-tenancy is enforced by the type system (PMS-139).** Service
  methods take a `tenant_id: TenantId` newtype that can only be
  produced from an authenticated claim via `CurrentUser::tenant()`, so
  a handler that forgets to pass the scope no longer compiles. See
  [Cross-cutting issues](#cross-cutting-issues) #8.
- **Tenant feature flag** (`multi-tenant`, default-on). PMS-262
  removed the `single-tenant` counterpart (and its shared
  `default_tenant_id()` / `Default for TenantContext`): multi-tenant
  is now the only mode and there is no shared-data fallback. The
  `/tenants` CRUD routes are still gated on `multi-tenant`.
- **Default tenant disposition** (`Uuid::from_u128(1)`, a.k.a.
  `OIDC_DEFAULT_TENANT_ID`): INFRA-ONLY. The only legitimate residents
  are platform `super_admin`s. Every non-admin who was historically
  parked there is backfilled into their own personal tenant on next
  Bunyip login (`place_bunyip_user` / `is_stuck_in_default`,
  `src/modules/auth/middleware.rs`), so no normal user shares data in
  it. Enforced end-to-end by the `tests/bunyip_login.rs` placement
  tests (PMS-262, PMS-245).

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
[`models.rs`](../src/modules/contacts/models.rs) (630),
[`website_probe.rs`](../src/modules/contacts/website_probe.rs).

**Endpoints:** the table below is the list, as registered in
[`contact_routes`](../src/modules/contacts/routes.rs). The router
exposes companies, contacts, sites and the company-industry lookup all
under `/api/v1/contacts/...`. The empty
`.nest("/companies", Router::new())` declared at
[`router.rs:45`](../src/api/router.rs#L45) is dead - it matches
nothing, so `/api/v1/companies` returns 404 instead of an alias. See
[Cross-cutting issues](#cross-cutting-issues) #11.

| Path | Method |
| --- | --- |
| `/api/v1/contacts/companies` | GET / POST |
| `/api/v1/contacts/companies/website-probe` | GET |
| `/api/v1/contacts/companies/:company_id` | GET / PUT / DELETE |
| `/api/v1/contacts/companies/:company_id/contacts` | GET |
| `/api/v1/contacts/companies/:company_id/sites` | GET |
| `/api/v1/contacts/contacts` | GET / POST |
| `/api/v1/contacts/contacts/field-values` | GET |
| `/api/v1/contacts/contacts/:contact_id` | GET / PUT / DELETE |
| `/api/v1/contacts/company-industries` | GET / POST |
| `/api/v1/contacts/company-industries/:id` | PUT / DELETE |
| `/api/v1/contacts/sites` | POST |
| `/api/v1/contacts/sites/:site_id` | GET / PUT / DELETE |

`GET /companies/website-probe?url=<value>` (PMS-805) resolves a website
on demand and reports whether https answers, whether http answers,
whether http redirects to https, whether the host gains or loses a
`www` prefix, and the final canonical URL. It is a static segment, so
it resolves ahead of `/companies/{company_id}`. It reads and writes no
tenant data; the tenant is the rate-limit key only. Both the reachable
and the unreachable verdict are 200s, because determining that a site
does not answer is a successful probe; input that cannot be a website
at all is a 400. `guard_outbound_url`
([`utils/net.rs`](../src/utils/net.rs)) gates every resolved address
before the first connect and again for every redirect hop, which is
what stops the endpoint being an SSRF primitive.

**The same gate everywhere a URL is not hardcoded (PMS-809).** The probe
was not the only outbound fetch of a caller-supplied URL, so
`guard_outbound_url` is shared by three callers: the probe (ports pinned
to 80/443), the ticket-automation `webhook` action
([`tickets/automation.rs`](../src/modules/tickets/automation.rs), which
now follows redirects itself so each hop is re-screened, and logs a
refusal with the rule id and the blocked address), and
`TacticalRmmProvider`
([`rmm/provider.rs`](../src/modules/rmm/provider.rs), which screens its
tenant-configured `api_url` before every request, refuses with an
`AppError::Configuration` that reaches `rmm_connections.last_error`, and
does not follow redirects). A second copy of the predicate or the resolve
loop fails `utils::net`'s `exactly_one_definition_in_the_crate` test.
`OUTBOUND_PRIVATE_ALLOWLIST` (hostnames, IPs, or CIDRs) is the operator
escape hatch for an on-premise integration; fetches whose URL comes from
operator env (Infisical, Stripe, the `OIDC_ISSUER` JWKS, the version
check) are deliberately out of scope.

**Contact child collections and the mirror rule (PMS-806).** A contact
carries an ordered list of typed phone numbers (`contact_phones`:
`phone_type` in `mobile`/`work`/`home`/`fax`/`other`, `number`,
`extension`, `is_primary`, `sort_order`) and links to any number of
companies (`contact_companies`: `company_id`, per-link `title`,
`is_primary`, `sort_order`, `UNIQUE (contact_id, company_id)`). Both are
tenant-scoped with their own `tenant_isolation` RLS policy and a partial
unique index enforcing one primary per contact
([`108_contact_phones_and_companies.sql`](../migrations/108_contact_phones_and_companies.sql)).

A contact's links are ordered by `(created_at, sort_order)`, and that
order is what "removing the primary promotes the OLDEST remaining link"
means. `created_at` alone is not enough: it defaults to `NOW()`, the
transaction timestamp, so every link written by one call shares a value
and the tiebreak fell through to a random `uuid_generate_v4()`
([`109_contact_company_link_order.sql`](../migrations/109_contact_company_link_order.sql),
PMS-815). `write_contact_companies` sets `sort_order` from the request
position on INSERT only, so a link that survives a rewrite keeps the
position it was created with.

The child tables are authoritative. `contacts.phone`, `.mobile`, `.fax`
and `.company_id` stay on the table as **maintained mirrors**, recomputed
from the child rows by
[`recompute_contact_mirrors`](../src/modules/contacts/service.rs) inside
the same transaction as every create and update - the single writer of
those four columns. The rule: `phone` = the primary entry's number,
`mobile` = the first `mobile`-type entry, `fax` = the first `fax`-type
entry, `company_id` = the primary link (NULL with no links). This is a
deliberate denormalization that keeps every pre-PMS-806 query, index,
seed fixture, portal lookup and the current SPA working while the SPA
catches up (MAPPS-481).

`CreateContactRequest` / `UpdateContactRequest` take optional `phones`
and `companies` arrays. Absent, the scalar fields drive the write and the
service materializes the matching child rows; present, they are
authoritative and the scalars in the same request are recomputed from
them. Reads that answer "which contacts belong to company X"
(`list_contacts`'s `company_id` filter, `get_company_contacts`, the
company list's `contact_count`) go through `contact_companies`, so a
contact is found through ANY of its links and counted once per company.
`phones` and `companies` are hydrated with one batched query each per
page, pinned by
[`contact_hydration_query_budget.rs`](../tests/contact_hydration_query_budget.rs).

Portal scoping is deliberately NOT broadened: a portal session still
resolves the contact's primary company only (PMS-807).

**Deleting a company unlinks its contacts (PMS-812).**
`contacts.company_id` is `ON DELETE SET NULL`
([`110_contacts_company_id_set_null.sql`](../migrations/110_contacts_company_id_set_null.sql)),
not the `ON DELETE CASCADE` it was created with in 004. `delete_company`
is the primary path: inside the same transaction as the company DELETE it
removes that company's `contact_companies` rows, promotes the oldest
remaining link on any contact that just lost its primary (the same rule
`write_contact_companies` applies), and recomputes the mirrors. The FK
action is the backstop for a direct SQL delete or a mirror that outlives
its link row.

A **company-less contact** - `company_id` NULL with no `contact_companies`
rows - is a first-class state, valid since PMS-402 (which made the column
nullable for the freeform `company_name` case). It reads back normally
from `GET /contacts/contacts/{id}` and stays in the contacts list; it just
appears under no company, so `GET /companies/{id}/contacts`, the
`company_id` list filter and `contact_count` never surface it. Every read
of `contacts.company_id` must therefore decode it as `Option<Uuid>`:
`PortalService::login` rejects a company-less contact with a logged 401
(there is nothing to scope a portal session to, since every portal read
takes `CurrentContact.company_id`), and email-intake's
`resolve_or_create_contact` falls back to the tenant's
`email_intake/default_company_id` setting.

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

**Schema touched:** `companies`, `contacts`, `contact_phones`,
`contact_companies`, `sites`.

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

#### `seed` (PMS-157; one route via `data_transfer`, PMS-679)

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

PMS-679 adds `SeedService::load_demo_data` -> `LoadDemoOutcome`, the
explicit-request counterpart to the auto-seed: it reuses the same
emptiness gate and `seed_rows`, but returns its outcome instead of
swallowing it, and only ever loads into an empty tenant (additive,
never wipes; the shared landing tenant is refused too). It is exposed
by the `data_transfer` module as admin-only `POST /api/v1/data/seed-demo`
(sharing the middleware's `SeedService` `Arc`), which the mokosh-apps
Settings -> Data "Load demo data" button calls. `MOKOSH_DEMO_SEED`
does not gate this path - it is an explicit operator action, not the
automatic first-visit seed.

**Schema touched:** `tenants` (the `demo_seeded` settings flag), plus
inserts into `companies`, `contacts`, `tickets`.

### Placeholder modules (14)

> **Superseded (2026-07-24, PMS-684).** This list is historical. The
> modules below (assets, audit, billing, calendar, contracts,
> knowledge_base, notifications, portal, projects, reports, rmm,
> settings, sla, time_tracking) now have real handlers merged in
> `api/router.rs`, and the 501 placeholder router no longer exists.
> Retained to document the original schema-to-handler mapping.

Each was a single-line `mod.rs` (`//! <name> module placeholder`) and
the router mapped each to a placeholder handler that returned
`HTTP 501 Not implemented yet`. Schema tables exist for every one of
these, so adding a real module is mostly handler + service work
against an existing schema.

| Module | Schema tables in [`001_initial_schema.sql`](../migrations/001_initial_schema.sql) | Client UI surface affected |
| --- | --- | --- |
| `assets` | `asset_types`, `assets`, `asset_relationships`, `configuration_items`, `credential_vault`, `asset_audit_log` | `/assets`, `/assets/new`, `/assets/:id` |
| `audit` | `audit_log` | none direct |
| `billing` | `invoices`, `invoice_sequences`, `invoice_lines`, `payments`, `payment_refunds`, `payment_gateway_configs`, `tax_rates` | `/invoices`, `/invoices/new`, `/invoices/:id`, `/payments`, `/payment-gateways`; PMS-711 Pay Now: `POST /portal/invoices/:id/pay`, `POST /stripe/webhooks/:tenant_id` (unauth, signature-verified) |
| `calendar` | `appointments`, `user_availability`, `time_off`, `on_call_schedules` | `/calendar`, `/dispatch` |
| `contracts` | `contracts`, `contract_items`, `contract_hour_balances`, `rate_cards`, `rate_card_items` | `/contracts`, `/contracts/new`, `/contracts/:id` |
| `knowledge_base` | `kb_categories`, `kb_articles`, `kb_article_versions` | `/kb`, `/kb/articles`, `/portal/kb` |
| `notifications` | `notification_channels`, `notification_templates`, `user_notification_preferences`, `notifications`, `notification_rules` | notification bell + `/settings/notifications`; PMS-808 preview: `POST /api/v1/notifications/preview` renders what `dispatch` would send for an `(event_type, context)` and queues/sends nothing (drives the MAPPS-482 preview affordance) |
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

> **Historical (2026-05-06 audit).** This list and the `F1..F14`
> fix list below are the findings of the 2026-05-06 audit, retained
> for the reasoning behind each fix. Several no longer hold: item 2
> in particular, because `/api/v1/portal/*` is a real router with
> its own contact-scoped auth middleware today. Read a claim here as
> a record of what was true on 2026-05-06, not as current state, and
> confirm it against the tree before acting on it. Rebuilding or
> freezing this catalog is tracked in PMS-849.

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
8. **Multi-tenancy: typed scoping rollout DONE (PMS-139).** A `TenantId`
   newtype ([`auth/tenant.rs`](../src/modules/auth/tenant.rs)) whose only
   in-crate constructor is `pub(crate)` and is reached solely via
   `CurrentUser::tenant()` (the `TenantScoped` trait), so a `TenantId` always
   traces back to an authenticated claim. Service methods that take
   `tenant_id: TenantId` can no longer be called with a bare `Uuid` (pinned by
   a `compile_fail` doctest on `TenantId`). **All request-scoped modules are
   migrated:** `reports` (the reference pattern - handlers use `u.tenant()`,
   service takes `TenantId`), `rmm`, `time_tracking`, `assets`, `projects`,
   `calendar`, `sla`, `contracts`, `knowledge_base`, `tenants`, `settings`,
   `contacts`, `billing`, plus all three cross-module hubs - `audit`
   (`audit_write` + `AuditService`), `notifications` (`dispatch`), and `tickets`
   (`TicketService`). Handlers derive the scope via `u.tenant()`; a new handler
   that forgets to pass it no longer compiles.

   The remaining `from_trusted` escape-hatch sites are all deliberate, each with
   a `// SAFETY:`/`// PMS-139:` note: the RMM ingest webhook (unauthenticated
   machine HMAC), the `tenants` super-admin handlers (they address an arbitrary
   path tenant, not the caller's claim, after a role guard), the portal feeds
   (KB / invoices / tickets - portal runs on contact sessions, not
   `CurrentUser`), the demo `seed`er and the `tenants` create path (trusted
   system actors seeding a claimed-or-minted id), the cross-tenant workers
   (calendar reminder, sla sweep, billing recurring sweep - they read tenant ids
   off DB-projected rows), and the `auth` module + `audit_auth_event` helper
   (the login/session path, which works off the raw JWT claim). The
   cross-tenant dispatcher/sweep workers stay `Uuid`-internal structs.

   The only surviving `tenant_id.get()` calls (6) are genuine `Uuid` boundaries,
   not transitional: the `PaymentResponse` / `TenantUsage` DTO fields and the
   `tenants` update `entity_id` carry a plain `Uuid`; `AuditCtx::system` is a
   `Uuid` context bag (the request-extractor DTO, tolerant of
   unauthenticated/system callers); and the ticket-automation webhook payload
   serialises the tenant as a `Uuid`. `tenants::copy_default_config` keeps its
   `Uuid` (it copies from a hardcoded default tenant into a freshly minted one -
   neither is a claim). This item is resolved.
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
    [`mokosh-apps/src/modules/...`](../../mokosh-apps/src/modules/).
    Each `mod.rs` uses `#[cfg(feature = "server")]` to omit handler
    and service code from the WASM build. Currently in lock-step;
    vulnerable to silent drift the moment one side is edited
    without porting.

## Proposed fixes

> **Historical (2026-05-06 audit).** Covered by the note under
> [Cross-cutting issues](#cross-cutting-issues): these are the
> 2026-05-06 proposals, and several have shipped since. F6 and F12
> below, and the `## Priority` table that ranks them, describe a 501
> placeholder router that no longer exists.

Concrete, scoped patches. IDs are referenced from per-module
sections above.

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

DTOs were ported to `mokosh-apps` byte-identical (5th
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

> **Does not run as written.** The snippet below addresses the API
> through a host port the dev stack no longer publishes and logs in
> as an account no migration creates. Rewriting it against the
> Traefik-routed stack is tracked in PMS-873; until then follow
> [`quickstart.md`](../quickstart.md).

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
```

Two things this surfaced at the 2026-05-06 audit:

1. `tickets` list comes back with empty `status.name`,
   `priority.name`, `company_name` etc. (validates F3).
2. `/api/v1/companies` (without the `/contacts/` prefix) returns 404
   (validates Cross-cutting #11).
