# mokosh-server specification

This document describes mokosh-server as implemented in the source tree: the crate manifests, `src/main.rs`, the router in
`src/api/router.rs`, the modules under `src/modules/`, the SQL files in `migrations/`, configuration loading in
`src/config/`, and the container build in `oci-build/Dockerfile`. Where a statement here and another document disagree,
the code is authoritative.

## 1. Purpose and scope

mokosh-server is the API server of a professional services automation (PSA) platform for managed service providers
(MSPs). It is a multi-tenant JSON-over-HTTP service backed by PostgreSQL. Each tenant is one MSP organization. The
users are the MSP's staff (administrators, managers, technicians, dispatchers, sales, finance), the MSP's client
contacts (through a separate contact portal plane), and platform administrators who operate the deployment.

It provides: service desk ticketing with SLAs and workflow rules; time tracking and timesheets; projects; calendar and
dispatch; contracts and rate cards; invoicing, quotes, credit notes, payments and expenses; assets and documentation; a
knowledge base; client company and contact management; notifications; reporting; and integrations with payment
processors, accounting systems, RMM tools, contact directories, an OIDC identity provider and object storage.

It does not serve a user interface. Any path that matches no route answers `404` with a small HTML page stating that
the host is an API endpoint (`not_a_frontend` in `src/api/router.rs`). The browser client is a separate repository that
shares the data-transfer types in the workspace crate `crates/mokosh-types`. Identity provisioning for the hosted
deployment profile is delegated to an external OIDC provider referred to in this document as the identity provider
(the `bunyip` provider name and `BUNYIP_*` variables in the code).

## 2. Architecture

### 2.1 Workspace

| Member | Kind | Role |
|---|---|---|
| `mokosh-server` (root package) | library `mokosh_server` plus binaries `mokosh-server` and `mokosh-bootstrap` | The application. Cargo features `multi-tenant` and `server` are both on by default. |
| `crates/mokosh-types` | library | Wire types shared with the browser client: auth, billing, contacts, forms, integrations, members, mileage, tenants, tickets, time tracking, sorting and validation helpers. |
| `crates/build-metadata` | library | Build-script logic called from the root `build.rs`; supplies the version banner data (git hash, describe string, build date). |
| `crates/mokosh-test-macros`, `crates/mokosh-test` | proc-macro and library | Test support only: the `#[mokosh_test]` attribute clones each test's database from one migrated template database. Dev-dependencies of the root package. |

Rust edition 2021; the toolchain is pinned in `rust-toolchain.toml` (channel `1.98.1`, with clippy and rustfmt).

### 2.2 Technology stack

- HTTP: axum 0.8 on tokio, tower and tower-http (CORS, tracing, gzip and brotli compression).
- Database: PostgreSQL through sqlx 0.8 (`runtime-tokio`, `postgres`, `migrate`); money values use `rust_decimal`.
- Authentication: `jsonwebtoken` (HS256 for server-issued tokens, asymmetric algorithms for identity-provider tokens),
  `argon2` for password and token hashing, `zxcvbn` for password strength, RFC 6238 TOTP built on `hmac` and `sha1`.
- Encryption and signatures: `aes-gcm` (AES-256-GCM) for secrets at rest, `hmac`, `sha2` and `constant_time_eq` for
  webhook signatures.
- Outbound: `reqwest` with rustls, `lettre` for SMTP (native TLS, pooled), a hand-written SigV4 signer for S3 storage,
  `quick-xml` for CardDAV responses, `calcard` for vCard parsing.
- Documents: `printpdf` renders PDFs for invoices, quotes, credit notes and statements (embedded Noto Sans fonts).
  `minijinja` renders knowledge-base templates. `rrule` expands recurring appointments at read time.
- Operations: `governor` for rate limiting, `moka` for caches, `ip2location` and a shared IP-enrichment crate for
  IP geolocation and proxy enrichment, `tracing` with `tracing-subscriber` for logs.
- Three shared first-party crates are git dependencies pinned by revision: Stripe signature verification and event
  parsing, IP enrichment, and the provider status report contract.

### 2.3 Runtime shape

`mokosh-server` is one long-running process. `src/main.rs` runs, in order:

1. If `argv[1]` names an operator subcommand (section 4.2), run it and exit.
2. Initialise `tracing` with `RUST_LOG` (default filter `info`), load a `.env` file, read the hosting profile
   (`MOKOSH_DEPLOYMENT_MODE`), and refuse to boot if a retired storage variable name is set.
3. Select the configuration provider and resolve every declared configuration key into one generation.
4. Build `AppConfig`; refuse to boot outside development/test if the essential deployment variables are unset or the
   secrets are weak (section 6.1).
5. Provision the two database roles if the migrator role cannot yet log in (needs `MOKOSH_ADMIN_DATABASE_URL`), open
   the two connection pools, and run migrations when `RUN_MIGRATIONS` is true (the default). A migration failure ends
   startup with a non-zero exit.
6. Create the first platform administrator when `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set and no platform admin
   exists. A failure here is logged as a warning and boot continues.
7. Initialise the application-tier secret providers, the deployment's OAuth client pairs (Google, Microsoft, Xero,
   Intuit), the cached product name, the mailer (the transport is verified at boot and a failure ends startup), the
   identity-provider token verifier, and the authentication provider chain.
8. Start the background scheduler (section 2.5), spawn the one-shot data movers, load the optional IP databases.
9. Build the router and serve it on `HOST:PORT` (defaults `0.0.0.0:8080`) with client connect info. There is no
   graceful-shutdown handler.

### 2.4 Request pipeline

Top-level router, outermost layer first: security headers, CORS, response compression, request tracing, JSON body
sanitising. The JSON sanitiser (`src/utils/text.rs`) cleans string values in JSON request bodies and forwards the parsed
tree to the `Json` extractor; it skips non-JSON bodies, bodies over 25 MiB, and the signature-verified prefixes
`/api/v1/bunyip/`, `/api/v1/rmm/alerts`, `/api/v1/rmm/status`, `/api/v1/stripe/`, `/api/v1/paypal/` and
`/api/v1/webhooks/`, whose bytes must reach the handler unchanged.

Route trees mounted by `create_api_router`:

| Mount | Contents | Layers |
|---|---|---|
| `/api/v1` | Staff API | error-envelope normaliser, shared extensions, contact-token middleware, staff auth middleware, first-visit demo seeding |
| `/api/v1/public` | Unauthenticated endpoints | per-IP rate limit (60 per minute), error-envelope normaliser |
| `/api/v1/contact` | Contact portal API | contact-token middleware, error-envelope normaliser |
| `/api/v1/bunyip` | Identity-provider webhooks and back-channel logout | error-envelope normaliser |
| `/api/v1/stripe`, `/api/v1/paypal`, `/api/v1/webhooks` | Payment and accounting webhooks | error-envelope normaliser |

Authentication is performed by middleware, which only records an `AuthState` in the request extensions. A route is
protected by declaring an extractor in the handler signature (`RequireAuth`, `RequireAdmin`, `RequireManager`,
`RequireFinance`, `RequireSuperAdmin`, the per-module gates, `DeploymentOperator`, `RequirePlatformAdmin`,
`RequireContactAuth`). A handler with none of these is open.

Tenant isolation: services open work with `Database::begin_with_tenant(tenant_id)`, which starts a transaction on the
request-serving pool and sets `app.current_tenant` for that transaction. Row level security policies read that setting
(section 5.2).

Errors: every failure is an `AppError` rendered as a JSON envelope `{"error": {"code", "message", "errors"?}}`. The
`normalize_error_envelope` layer rewrites plain-text extractor rejections into the same envelope. Rate-limit
rejections answer `429` with `Retry-After`. A deleted account answers `410` with code `ACCOUNT_DELETED`. An expired
token answers `401` with a `WWW-Authenticate: Bearer` challenge that distinguishes expired, invalid and ended-session
credentials.

### 2.5 Background jobs

All periodic jobs run on the shared scheduler (`src/scheduler/mod.rs`): one tokio task per job, fixed interval, missed
ticks skipped, the first tick fires immediately at startup, tick errors are logged at `warn` and the loop continues.

| Job | Interval | Behaviour |
|---|---|---|
| Notification dispatcher | 5 s | Drains pending `notifications` rows with `SKIP LOCKED`; delivers `in_app` and `email`; any other channel is marked failed with "no transport registered". |
| RMM sync | 60 s | For each active RMM connection past its sync interval, pulls devices, upserts device mappings and assets, records `sync_status` and `last_error`. |
| Contact sync runner | 60 s (also woken on demand) | Executes queued contact import runs. |
| SLA sweep | 60 s | Enqueues at-risk and breach notifications once per milestone (ledger `sla_notifications`). |
| Calendar reminders | 60 s | Sends appointment reminders. |
| Scheduled reports, scheduled dashboards | 60 s each | Run cron-scheduled saved reports and dashboards and email the recipient. |
| Feature-toggle refresh, asset signature detector refresh | 60 s each | Reload in-memory snapshots from the database. |
| Contract lifecycle | 1 h | Renews (when `auto_renew`) or expires active contracts past `end_date`. |
| Recurring invoicing | 1 h | Creates one draft invoice per due billing period of each active recurring contract, idempotent through `contract_invoice_runs`. |
| Invoice reminders | 1 h | Sends invoice reminders. |
| Grant invitation expiry sweep | 1 h | Expires stale grant invitations. |
| Status retention | 6 h | Prunes old status observations. |

One-shot tasks started at boot (`scheduler/one_shot.rs`): move knowledge-base attachments, tenant logos, branding assets
and payment-gateway credentials to their current storage layout, and clean up a retired Google client secret.

### 2.6 Provider seams

Five capabilities are selected by name and resolved once at boot (`src/utils/deployment.rs`). Defaults come from the
hosting profile set by `MOKOSH_DEPLOYMENT_MODE` (`self-hosted` or `saas`):

| Capability | Providers | self-hosted default | saas default |
|---|---|---|---|
| Configuration | `environment` | `environment` | `environment` |
| Tenant secrets | `database`, `infisical` | `database` | `database` |
| Authentication | `local`, `bunyip` | `local` | `bunyip`, `local` |
| Email | `log`, `smtp`, `bunyip` | `log` | `smtp` |
| Object storage | `local`, `s3` | `local` | `local` |

Further seams: application-tier secrets (`APP_SECRET_BACKEND`: `environment`, `file`, `database`, `infisical`, `bunyip`),
and the payment provider interface (`stripe`, `paypal`). An unrecognised provider name ends startup naming the legal
values. The configuration seam also contains `file`, `database` and `bunyip` providers, which only the operator CLI
chain builder (`CONFIG_PROVIDERS`) constructs; the server process itself reads configuration from `environment`.

## 3. Functional requirements

Each statement is observable through the interfaces in section 4.

### 3.1 Identity, sessions and tenancy

- Staff log in with email and password at `POST /api/v1/auth/login`. A user belonging to several tenants selects one
  (`select-tenant`) or switches (`switch-tenant`). Memberships are listed at `GET /api/v1/auth/memberships`.
- Server-issued access tokens are HS256 JWTs with issuer and audience `mokosh-server`, valid 1 hour; refresh tokens
  are valid 7 days. Refresh, logout, logout-all and per-session revocation are supported.
- When the identity-provider verifier is configured (`OIDC_ISSUER` and `OIDC_AUDIENCE`), bearer tokens of type `at+jwt`
  are verified against the provider's JWKS first; a verified identity is mirrored into the local `users` table on first
  sight. Provider roles never map to `super_admin`. First-sight identities without an invitation are rejected unless
  `ALLOW_UNINVITED_BUNYIP_SIGNUP` is true and the provider has verified the email.
- A session the identity provider ended (back-channel logout) is refused even if the token has not expired. A deleted
  provider account tombstones the local user (soft delete, sessions and API keys removed).
- A deactivated user or a non-active tenant is refused on the next request, not at token expiry.
- TOTP multi-factor authentication can be enrolled, enabled and disabled. Recovery codes are accepted in place of a code.
  After 3 failed codes the account is locked for 30 seconds, doubling per further failure up to 1 hour.
- With `LOGIN_APPROVAL_ENABLED`, a login from a new country (needs the IP2Location database) or a new device (a
  client-supplied `device_id`) is withheld after password and MFA succeed until the single-use emailed code is sent back
  with the login request (5 wrong attempts destroy the challenge). With the flag off, a new-country login only triggers
  an alert.
- Password reset by emailed token (`forgot-password`, `reset-password`); a user-invite "set password" context lookup.
- Users can create personal API keys (prefix `psa_`, stored hashed, listed by prefix, revocable). The authentication
  middleware does not read the `api_keys` table: a key is not accepted as a request credential.
- Roles: `super_admin`, `admin`, `manager`, `technician`, `dispatcher`, `sales`, `finance`. Platform administrators are
  a separate plane (`platform_admins`, `POST /api/v1/platform/login`).
- Tenants have status `active`, `suspended` or `cancelled`. Platform admins create, list, suspend and activate tenants.
  A signed-in user can create an additional organization or, with an identity token, self-serve their first one.
  `MOKOSH_MAX_TENANTS` caps tenant creation (409 at the cap), re-read on each create.
- Teams with leader or member roles; per-tenant module switches (`/tenants/{id}/modules/{module}`, `/settings/modules`).
- Grant invitations let an organization owner invite an existing identity into the organization; invitees accept or
  decline by token or from their own list. When the directory client is configured, invitees are looked up at the
  identity provider.

### 3.2 Service desk

- Tickets carry number, title, description, status, priority, queue, optional type, category and subcategory, source
  (`portal`, `email`, `phone`, `api`, `chat`, `rmm`, `internal`), company, contact, site, assignee, team, parent ticket,
  contract, SLA due times, scheduling window, estimated and actual hours, billable flag, billing status
  (`not_billed`, `ready_to_bill`, `billed`, `prepaid`), asset, procedure article, tags and custom fields.
- Statuses, priorities, queues, types, categories and per-user saved views are tenant-configurable.
- Agents assign, reopen, add notes (types `internal`, `public`, `resolution`, `time_entry`) and attach files to tickets and notes; inline images are
  supported.
- Workflow rules fire inside the ticket transaction on `ticket.created`, `ticket.status_changed` and
  `ticket.priority_changed`. Actions include assign, set priority, set status, add tag and add internal note; cascading
  transitions are bounded by a per-tenant depth cap (default 3). Runs are listed per ticket.
- Rows in `ticket_automation_rules` are evaluated by the ticket service (`AutomationEngine`), including a `webhook` action
  that passes the outbound URL guard (section 7.3). No HTTP route or other code in `src` inserts such rows.
- Ticket templates; approval requests on tickets, time entries, change requests and quotes with a pending-approvals
  inbox and decision endpoint.
- Email-to-ticket intake: a mail gateway posts parsed messages to `POST /api/v1/email-intake` with a tenant intake
  bearer token. Messages are deduplicated by Message-Id, threaded by references, matched to a contact by sender, and
  create `email`-source tickets. Tokens are managed by admins.
- SLA: policies with targets, business hours with time zones, holiday calendars, per-ticket evaluation, status
  `on_track`, `warning`, `breached` or `not_applicable`, at-risk and breach notifications.
- RMM alerts posted to `POST /api/v1/rmm/alerts` (HMAC-signed with the connection secret) create tickets according to
  alert rules.

### 3.3 Time, projects, calendar

- Time entries with work types, billable flag, billing status and approval status (`draft`, `pending`, `approved`,
  `rejected`); rounding rules; start/stop timers; workday clock-in/out with breaks and editable segments; weekly
  timesheets submitted, withdrawn, approved or rejected per user and week start; mileage entries.
- Projects with phases, tasks, task statuses, task dependencies and project types; project summary.
- Appointments with RFC 5545 recurrence expanded in memory over the requested range, user availability windows, time
  off with approval, on-call schedules and "who is on call now", scheduling templates, and an aggregated dispatch board.

### 3.4 Commercial

- Contracts (statuses `draft`, `active`, `expired`, `cancelled`, `renewed`) with items, hour balances and rate cards.
- Invoices (statuses `draft`, `pending`, `sent`, `paid`, `partially_paid`, `void`, `written_off`) created manually or
  from time entries; write-off, void, amend, PDF, delivery options, payment readiness, payments list; products, tax rates
  with lookup, payment terms; credit notes (`issued`, `void`) with PDF; customer statements with PDF; manual payment
  recording and deletion.
- Online payment through Stripe or PayPal using each tenant's own gateway credentials (stored through the tenant secret
  provider). Inbound provider webhooks are verified per tenant before any parsing and reconciled idempotently; webhook
  deliveries are recorded and listed.
- Quotes (statuses `draft`, `submitted`, `approved`, `rejected`, `sent`, `accepted`, `declined`, `expired`, `converted`,
  `cancelled`) with lines, send, PDF, accept, decline and conversion; opportunities with stages `lead`, `qualified`,
  `proposal`, `negotiation`, `won`, `lost`.
- Expenses (`draft`, `submitted`, `approved`, `reimbursed`, `rejected`), vendors, expense categories, bills (`draft`,
  `approved`, `paid`, `void`) with bill payments.
- Delegated accounting: when the feature switches `delegated_invoice_issuer` and `delegated_bills` are on and a tenant
  has connected Xero or QuickBooks with the matching capability, invoices and bills are raised in that system.
  Mappings of companies, products, vendors, expense accounts and people to provider records are managed under
  `/invoice-issuer-mappings`. Xero and QuickBooks webhooks are verified by HMAC-SHA256.
- Invoices and quotes can be delivered by email through the configured mailer; per-user sends of request links and
  invoice emails are limited to 20 per hour.

### 3.5 Clients, assets, knowledge

- Companies (with industries, status, portal slug), contacts, sites, contact phones and company links; a website probe;
  deletion preview; contact notes.
- Portal access for contacts: grant, resend, revoke; portal roles with capabilities; access requests that staff resolve.
- Contact import from Google, Microsoft, iCloud (CardDAV) and `.vcf` upload: connect, preview, queued runs, a review
  queue for ambiguous matches, per-field locks, unlink and remove-imported-data. Import is one-way (read-only scopes).
- Assets with types and typed custom fields, relationships, impact view, configuration items, an encrypted credential
  vault whose reveal is audited, per-asset audit log, search with facets and bulk create (behind feature switches
  `assets_search_v2` and `assets_catalog`), asset models and templates. A per-company documentation view composes assets,
  credential references (never secret values) and knowledge-base articles.
- Knowledge base: categories, articles with drafts, versions and restore, publish states (`draft`, `published`,
  `archived`), attachments, comments with mentions and resolve, helpful votes, template rendering with a values map,
  ticket-driving article ranking and measured duration.
- Forms: definitions with ordered fields (types `text`, `textarea`, `email`, `date`, `select`, `boolean`) and the rule
  `required_if`; drafts, submissions, and tokenised request links that let a client submit a form without an account.
  Unknown field types or rules written by a newer version are read tolerantly but rejected on write.

### 3.6 Platform services

- Notifications: channels, templates, per-user preferences, rules, an in-app inbox, preview and dispatch endpoints.
- Search across tickets, contacts, companies, assets and projects (`GET /api/v1/search?q=`), tenant-scoped.
- Reports: dashboard, tickets, time, billing, request types, projects, clients, a custom report builder over a
  whitelisted catalog, CSV export, saved reports and dashboards with cron schedules.
- Client service status: monitored systems and observations posted by an HMAC-signed endpoint (source `tactical_rmm`),
  current-status lookup, backup success rate and uptime reports; observations older than 13 months are deleted.
- Audit log of entity changes with admin list and CSV export, and per-entity history.
- Tenant data export as a versioned JSON document (all tables with `tenant_id` minus secrets, identity and audit tables)
  and import; an admin action to load demo data. Demo data is seeded automatically on first visit in the `production`
  environment only, unless `MOKOSH_DEMO_SEED` is truthy.
- Branding: tenant logo, favicon and background; company-scoped logo, favicon and background (also manageable by a
  portal contact for their own company); public GET of these assets.
- Deployment-wide settings for the operator: SMTP relay settings with test send and verify, product name, the Google
  contacts OAuth client, feature switches, provider status report, IP enrichment lookup.
- Version information and an opt-in update check against `MOKOSH_UPDATE_CHECK_URL` (reports `disabled` and makes no
  outbound request when unset).

## 4. Interfaces

### 4.1 HTTP API

All paths are relative to the server root. Bodies and responses are JSON unless stated (attachments, logos and PDFs are
binary; uploads are `multipart/form-data`). List endpoints take `PaginationParams` query parameters and return a
paginated envelope. Errors use the envelope in section 2.4.

Credentials: staff and platform routes take `Authorization: Bearer <token>`. Contact portal routes take a bearer token
or the `mokosh:contact_token` cookie. Webhook and machine endpoints authenticate themselves as described after the
route tables. Routes below are listed as registered; the guard on each is the extractor in its handler:

| Area | Guard observed in handlers |
|---|---|
| Auth, tickets, contacts and companies, notifications, SLA, teams, search, dashboards, saved reports | `RequireAuth`; configuration writes add `RequireAdmin`; some add `RequireManager` |
| Billing, quotes, expenses, invoice-issuer mappings | module gate `billing`; many routes also `RequireFinance` |
| Contracts | module gate `contracts`; many routes also `RequireFinance` |
| Projects | module gate `projects`; some `RequireAdmin` |
| Calendar, dispatch | module gate `calendar`; some `RequireManager` |
| Assets, asset catalog, company documentation | module gate `assets`; some `RequireAdmin` |
| Knowledge base | module gate `knowledge_base`; some `RequireManager` |
| RMM connections, mappings, alert rules | module gate `rmm_integration`; `RequireAdmin` on writes |
| Reports | module gate `reports`; billing and clients reports also `RequireFinance` |
| Time entries, timers, workday, mileage, work types | module gate `time_tracking`; timesheet and approval routes use the `timesheets` gate |
| Workflow rules, ticket templates, email intake tokens, form definitions | `RequireAdminUser` (admin or super admin) |
| Audit log list and export, data export, import and demo seed, IP enrichment | `RequireAdmin` |
| Tenant list, create, suspend, activate | platform admin bearer |
| Per-tenant get, update, usage, module config | platform admin bearer or a member of that tenant (`TenantOrPlatformCaller`) |
| SMTP settings, product name, Google contacts client, feature switches | `DeploymentOperator`: a platform admin bearer or an admin of the system tenant |
| Provider status (JSON and HTML) | admin session, or the identity provider's machine credential as HTTP Basic; refresh needs an admin session |

A module gate answers `404` when the module is disabled for the tenant.

#### Service and status (no authentication)

```text
GET                    /api/v1/health
GET                    /api/v1/ready
GET                    /api/v1/version
GET                    /api/v1/version/check
GET                    /api/v1/providers
```

#### Authentication, sessions, users

```text
POST                   /api/v1/auth/login
POST                   /api/v1/auth/select-tenant
POST                   /api/v1/auth/switch-tenant/{tenant_id}
POST                   /api/v1/auth/logout
POST                   /api/v1/auth/logout-all
POST                   /api/v1/auth/refresh
POST                   /api/v1/auth/forgot-password
POST                   /api/v1/auth/reset-password
GET                    /api/v1/auth/set-password/context/{token}
GET                    /api/v1/auth/me
PUT                    /api/v1/auth/me
GET                    /api/v1/auth/memberships
POST                   /api/v1/auth/me/complete-onboarding
PUT                    /api/v1/auth/me/password
GET                    /api/v1/auth/me/sessions
DELETE                 /api/v1/auth/me/sessions/{session_id}
POST                   /api/v1/auth/me/mfa/setup
POST                   /api/v1/auth/me/mfa/enable
POST                   /api/v1/auth/me/mfa/disable
GET                    /api/v1/auth/me/api-keys
POST                   /api/v1/auth/me/api-keys
DELETE                 /api/v1/auth/me/api-keys/{key_id}
GET                    /api/v1/auth/directory
GET                    /api/v1/auth/users
POST                   /api/v1/auth/users
GET                    /api/v1/auth/users/{user_id}
PUT                    /api/v1/auth/users/{user_id}
```

#### Platform plane (platform admins)

```text
POST                   /api/v1/platform/login
PUT                    /api/v1/platform/me/password
POST                   /api/v1/platform/me/mfa/setup
POST                   /api/v1/platform/me/mfa/enable
POST                   /api/v1/platform/me/mfa/disable
```

#### Grant invitations

```text
GET                    /api/v1/grants/invitations/by-token/{token}
POST                   /api/v1/grants/invitations/by-token/{token}/accept
POST                   /api/v1/grants/invitations/by-token/{token}/decline
POST                   /api/v1/grants/invitations
GET                    /api/v1/grants/invitations
DELETE                 /api/v1/grants/invitations/{id}
GET                    /api/v1/my-grants/invitations
POST                   /api/v1/my-grants/invitations/{id}/accept
POST                   /api/v1/my-grants/invitations/{id}/decline
DELETE                 /api/v1/my-grants/{id}
```

#### Tenants, teams, members, invitations

```text
GET                    /api/v1/tenants
POST                   /api/v1/tenants
POST                   /api/v1/tenants/self-serve
POST                   /api/v1/tenants/additional
GET                    /api/v1/tenants/current
PUT                    /api/v1/tenants/current
PUT                    /api/v1/tenants/current/organization
PUT                    /api/v1/tenants/current/logo
DELETE                 /api/v1/tenants/current/logo
GET                    /api/v1/tenants/{tenant_id}
PUT                    /api/v1/tenants/{tenant_id}
POST                   /api/v1/tenants/{tenant_id}/suspend
POST                   /api/v1/tenants/{tenant_id}/activate
GET                    /api/v1/tenants/{tenant_id}/usage
GET                    /api/v1/tenants/{tenant_id}/modules/{module}
PUT                    /api/v1/tenants/{tenant_id}/modules/{module}
GET, POST              /api/v1/teams
GET, PUT, DELETE       /api/v1/teams/{team_id}
GET, POST              /api/v1/teams/{team_id}/members
PUT, DELETE            /api/v1/teams/{team_id}/members/{user_id}
GET                    /api/v1/me/teams
GET                    /api/v1/members
GET, POST              /api/v1/invitations
DELETE                 /api/v1/invitations/{id}
```

#### Contacts, companies, sites

```text
GET                    /api/v1/contacts/companies
POST                   /api/v1/contacts/companies
GET                    /api/v1/contacts/companies/website-probe
GET                    /api/v1/contacts/companies/{company_id}
PUT                    /api/v1/contacts/companies/{company_id}
DELETE                 /api/v1/contacts/companies/{company_id}
GET                    /api/v1/contacts/companies/{company_id}/deletion-preview
GET                    /api/v1/contacts/companies/{company_id}/contacts
GET                    /api/v1/contacts/companies/{company_id}/sites
GET, POST              /api/v1/contacts/companies/{company_id}/portal-roles
GET, PUT, DELETE       /api/v1/contacts/companies/{company_id}/portal-roles/{role_id}
GET                    /api/v1/contacts/contacts
POST                   /api/v1/contacts/contacts
GET                    /api/v1/contacts/contacts/field-values
GET                    /api/v1/contacts/contacts/{contact_id}
PUT                    /api/v1/contacts/contacts/{contact_id}
DELETE                 /api/v1/contacts/contacts/{contact_id}
GET                    /api/v1/contacts/contacts/portal-roles
POST                   /api/v1/contacts/contacts/{contact_id}/grant-portal-access
POST                   /api/v1/contacts/contacts/{contact_id}/resend-portal-invite
POST                   /api/v1/contacts/contacts/{contact_id}/revoke-portal-access
GET, PUT               /api/v1/contacts/contacts/{contact_id}/portal-roles
GET                    /api/v1/contacts/contacts/{contact_id}/access-requests
POST                   /api/v1/contacts/contacts/access-requests/{request_id}/resolve
GET, POST              /api/v1/contacts/company-industries
PUT, DELETE            /api/v1/contacts/company-industries/{id}
POST                   /api/v1/contacts/sites
GET                    /api/v1/contacts/sites/{site_id}
PUT                    /api/v1/contacts/sites/{site_id}
DELETE                 /api/v1/contacts/sites/{site_id}
GET                    /api/v1/contacts/{contact_id}/notes
GET                    /api/v1/portal-roles
POST                   /api/v1/portal-roles
GET                    /api/v1/portal-roles/capabilities
GET                    /api/v1/portal-roles/{id}
PUT                    /api/v1/portal-roles/{id}
DELETE                 /api/v1/portal-roles/{id}
GET                    /api/v1/companies/{company_id}/documentation
PUT, DELETE            /api/v1/companies/{company_id}/{asset}
PUT, DELETE            /api/v1/tenants/current/branding/{asset}
```

#### Tickets

```text
GET                    /api/v1/tickets
POST                   /api/v1/tickets
GET                    /api/v1/tickets/{ticket_id}
GET                    /api/v1/tickets/{ticket_id}/sla
PUT                    /api/v1/tickets/{ticket_id}
PATCH                  /api/v1/tickets/{ticket_id}
DELETE                 /api/v1/tickets/{ticket_id}
POST                   /api/v1/tickets/{ticket_id}/assign
POST                   /api/v1/tickets/{ticket_id}/approvals/request
POST                   /api/v1/tickets/{ticket_id}/reopen
POST                   /api/v1/tickets/{ticket_id}/attachments
GET                    /api/v1/tickets/{ticket_id}/notes
POST                   /api/v1/tickets/{ticket_id}/notes
PUT                    /api/v1/tickets/{ticket_id}/notes/{note_id}
GET, POST              /api/v1/tickets/statuses
PUT, DELETE            /api/v1/tickets/statuses/{id}
GET, POST              /api/v1/tickets/priorities
PUT, DELETE            /api/v1/tickets/priorities/{id}
GET, POST              /api/v1/tickets/queues
PUT, DELETE            /api/v1/tickets/queues/{id}
GET, POST              /api/v1/tickets/types
PUT, DELETE            /api/v1/tickets/types/{id}
GET, POST              /api/v1/tickets/categories
PUT, DELETE            /api/v1/tickets/categories/{id}
GET, POST              /api/v1/tickets/saved-views
PUT, DELETE            /api/v1/tickets/saved-views/{id}
POST                   /api/v1/tickets/{ticket_id}/attachments/inline
GET, POST              /api/v1/tickets/{ticket_id}/notes/{note_id}/attachments
GET, DELETE            /api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}
GET, POST              /api/v1/ticket-templates
GET, PATCH, DELETE     /api/v1/ticket-templates/{id}
GET, POST              /api/v1/workflow-rules
GET, PATCH, DELETE     /api/v1/workflow-rules/{id}
GET                    /api/v1/tickets/{id}/workflow-runs
GET, POST              /api/v1/tickets/{ticket_id}/approvals
GET, POST              /api/v1/time-entries/{entity_id}/approvals
GET, POST              /api/v1/change-requests/{entity_id}/approvals
GET, POST              /api/v1/quotes/{entity_id}/approvals
GET                    /api/v1/approvals/pending
GET                    /api/v1/approvals/pending/count
POST                   /api/v1/approvals/{id}/decision
DELETE                 /api/v1/approvals/{id}
```

#### Time tracking, mileage

```text
GET, POST              /api/v1/work-types
PUT, DELETE            /api/v1/work-types/{id}
GET, POST              /api/v1/time-entries
GET                    /api/v1/time-entries/summary
GET, PUT, DELETE       /api/v1/time-entries/{id}
GET                    /api/v1/timesheets
POST                   /api/v1/timesheets/{user_id}/{week_start}/submit
POST                   /api/v1/timesheets/{user_id}/{week_start}/withdraw
POST                   /api/v1/timesheets/{user_id}/{week_start}/approve
POST                   /api/v1/timesheets/{user_id}/{week_start}/reject
GET                    /api/v1/timers/active
POST                   /api/v1/timers/start
POST                   /api/v1/timers/{id}/stop
GET                    /api/v1/workday
POST                   /api/v1/workday/clock-in
POST                   /api/v1/workday/clock-out
POST                   /api/v1/workday/break/start
POST                   /api/v1/workday/break/end
PUT, DELETE            /api/v1/workday/segments/{id}
GET, POST              /api/v1/time-rounding-rules
PUT, DELETE            /api/v1/time-rounding-rules/{id}
GET, POST              /api/v1/mileage-entries
GET, PUT, DELETE       /api/v1/mileage-entries/{id}
```

#### Projects

```text
GET, POST              /api/v1/projects
GET                    /api/v1/projects/summary
GET, PUT, DELETE       /api/v1/projects/{id}
GET, POST              /api/v1/projects/{id}/phases
PUT, DELETE            /api/v1/phases/{phase_id}
GET, POST              /api/v1/task-statuses
PUT, DELETE            /api/v1/task-statuses/{id}
GET, POST              /api/v1/project-types
PUT, DELETE            /api/v1/project-types/{id}
GET, POST              /api/v1/projects/{id}/tasks
GET, PUT, DELETE       /api/v1/tasks/{id}
POST, DELETE           /api/v1/tasks/{id}/depends-on/{other}
```

#### Calendar and dispatch

```text
GET, POST              /api/v1/appointments
GET                    /api/v1/calendar/appointments
GET, PUT, DELETE       /api/v1/appointments/{id}
GET, PUT               /api/v1/users/{user_id}/availability
GET, POST              /api/v1/time-off
GET, DELETE            /api/v1/time-off/{id}
POST                   /api/v1/time-off/{id}/approval
GET, POST              /api/v1/on-call-schedules
PUT, DELETE            /api/v1/on-call-schedules/{id}
GET                    /api/v1/on-call/now
GET, POST              /api/v1/scheduling-templates
GET, PUT, DELETE       /api/v1/scheduling-templates/{id}
GET                    /api/v1/dispatch
```

#### Contracts, SLA

```text
GET, POST              /api/v1/contracts
GET, PUT, DELETE       /api/v1/contracts/{id}
GET, POST              /api/v1/contracts/{id}/items
PUT, DELETE            /api/v1/contract-items/{id}
GET                    /api/v1/contracts/{id}/hour-balance
GET, POST              /api/v1/rate-cards
GET, PUT, DELETE       /api/v1/rate-cards/{id}
GET, POST              /api/v1/rate-cards/{id}/items
DELETE                 /api/v1/rate-card-items/{id}
GET, POST              /api/v1/sla/policies
GET, PUT, DELETE       /api/v1/sla/policies/{id}
GET, POST              /api/v1/sla/policies/{id}/targets
DELETE                 /api/v1/sla/targets/{id}
GET, POST              /api/v1/sla/business-hours
PUT, DELETE            /api/v1/sla/business-hours/{id}
GET, POST              /api/v1/sla/holiday-calendars
PUT, DELETE            /api/v1/sla/holiday-calendars/{id}
POST                   /api/v1/sla/tickets/{id}/evaluate
```

#### Billing

```text
GET, POST              /api/v1/invoices
GET                    /api/v1/invoices/summary
POST                   /api/v1/invoices/from-time-entries
GET, PUT               /api/v1/invoices/{invoice_id}
POST                   /api/v1/invoices/{invoice_id}/write-off
POST                   /api/v1/invoices/{invoice_id}/void
POST                   /api/v1/invoices/{invoice_id}/amend
GET                    /api/v1/invoices/{invoice_id}/pdf
GET                    /api/v1/invoices/{invoice_id}/delivery-options
POST                   /api/v1/invoices/{invoice_id}/pay
GET                    /api/v1/invoices/{invoice_id}/payments
GET                    /api/v1/invoices/{invoice_id}/payment-readiness
GET, POST              /api/v1/products
GET, PUT, DELETE       /api/v1/products/{product_id}
GET                    /api/v1/statements
GET                    /api/v1/statements/pdf
GET, POST              /api/v1/credit-notes
GET                    /api/v1/credit-notes/{credit_note_id}
GET                    /api/v1/credit-notes/{credit_note_id}/pdf
POST                   /api/v1/credit-notes/{credit_note_id}/void
GET, POST              /api/v1/payments
DELETE                 /api/v1/payments/{payment_id}
GET, PUT               /api/v1/payment-gateways
GET                    /api/v1/payment-gateways/webhook-endpoints
GET                    /api/v1/payment-gateways/webhook-deliveries
DELETE                 /api/v1/payment-gateways/{provider}
POST                   /api/v1/payment-gateways/{provider}/check
GET, POST              /api/v1/tax-rates
PUT, DELETE            /api/v1/tax-rates/{id}
GET                    /api/v1/tax-rates/lookup
GET, POST              /api/v1/payment-terms
PUT, DELETE            /api/v1/payment-terms/{id}
GET                    /api/v1/invoice-issuer-mappings/companies
PUT                    /api/v1/invoice-issuer-mappings/companies/{provider}/{company_id}
GET                    /api/v1/invoice-issuer-mappings/products
PUT                    /api/v1/invoice-issuer-mappings/products/{provider}/{product_id}
GET                    /api/v1/invoice-issuer-mappings/vendors
PUT                    /api/v1/invoice-issuer-mappings/vendors/{provider}/{vendor_id}
GET                    /api/v1/invoice-issuer-mappings/expense-accounts
PUT                    /api/v1/invoice-issuer-mappings/expense-accounts/{provider}/{category_id}
GET                    /api/v1/invoice-issuer-mappings/people
PUT                    /api/v1/invoice-issuer-mappings/people/{provider}/{user_id}
GET                    /api/v1/integrations/invoice-issuer/{provider}
POST                   /api/v1/integrations/invoice-issuer/{provider}/authorize
POST                   /api/v1/integrations/invoice-issuer/{provider}/disconnect
PUT                    /api/v1/integrations/invoice-issuer/{provider}/bills
PUT                    /api/v1/integrations/invoice-issuer/{provider}/payment-account
GET, POST              /api/v1/quotes
GET, PUT, DELETE       /api/v1/quotes/{quote_id}
POST                   /api/v1/quotes/{quote_id}/send
GET                    /api/v1/quotes/{quote_id}/delivery-options
POST                   /api/v1/quotes/{quote_id}/convert
POST                   /api/v1/quotes/{quote_id}/accept
POST                   /api/v1/quotes/{quote_id}/decline
GET                    /api/v1/quotes/{quote_id}/pdf
POST                   /api/v1/quotes/{quote_id}/lines
PUT, DELETE            /api/v1/quotes/{quote_id}/lines/{line_id}
GET, POST              /api/v1/vendors
GET, PUT, DELETE       /api/v1/vendors/{id}
GET, POST              /api/v1/expense-categories
PUT                    /api/v1/expense-categories/{id}
GET, POST              /api/v1/bills
GET                    /api/v1/bills/{id}
POST                   /api/v1/bills/{id}/approve
POST                   /api/v1/bills/{id}/void
GET, POST              /api/v1/bills/{id}/payments
GET, POST              /api/v1/expenses
GET                    /api/v1/expenses/{id}
POST                   /api/v1/expenses/{id}/submit
POST                   /api/v1/expenses/{id}/approve
POST                   /api/v1/expenses/{id}/reject
POST                   /api/v1/expenses/{id}/reimburse
```

#### Assets, documentation

```text
GET, POST              /api/v1/asset-types
PUT, DELETE            /api/v1/asset-types/{id}
GET, POST              /api/v1/assets
POST                   /api/v1/assets/search
POST                   /api/v1/assets/search/facets
POST                   /api/v1/assets/bulk-create
POST                   /api/v1/assets/exists
GET, PUT, PATCH, DELETE /api/v1/assets/{id}
GET, POST              /api/v1/assets/{id}/relationships
DELETE                 /api/v1/asset-relationships/{id}
GET                    /api/v1/assets/{id}/impact
POST                   /api/v1/assets/{id}/report-issue
GET, POST              /api/v1/assets/{id}/configuration-items
GET, DELETE            /api/v1/configuration-items/{id}
GET, POST              /api/v1/assets/{id}/credentials
GET, DELETE            /api/v1/credentials/{id}
GET                    /api/v1/assets/{id}/audit-log
GET, POST              /api/v1/asset-models
GET                    /api/v1/asset-models/signature-detector
GET, PUT, DELETE       /api/v1/asset-models/{id}
GET, POST              /api/v1/asset-templates
GET, PUT, DELETE       /api/v1/asset-templates/{id}
```

#### Knowledge base

```text
GET, POST              /api/v1/kb/categories
PUT, DELETE            /api/v1/kb/categories/{id}
GET, POST              /api/v1/kb/articles
GET, PUT, DELETE       /api/v1/kb/articles/{id}
GET, PUT, DELETE       /api/v1/kb/articles/{id}/draft
GET                    /api/v1/kb/articles/{id}/versions
POST                   /api/v1/kb/articles/{id}/versions/{version_number}/restore
POST                   /api/v1/kb/articles/{id}/render
POST                   /api/v1/kb/articles/{id}/helpful
POST                   /api/v1/kb/articles/{id}/not_helpful
GET                    /api/v1/kb/articles/{id}/vote
GET                    /api/v1/kb/top-ticket-driving-articles
GET                    /api/v1/kb/articles/{id}/measured-duration
GET                    /api/v1/kb/articles/{id}/tickets
GET, POST              /api/v1/kb/articles/{id}/comments
PUT, DELETE            /api/v1/kb/comments/{id}
POST                   /api/v1/kb/comments/{id}/resolve
POST                   /api/v1/kb/comments/{id}/unresolve
GET, POST              /api/v1/kb/articles/{id}/attachments
DELETE                 /api/v1/kb/articles/{id}/attachments/{attachment_id}
GET                    /api/v1/kb/attachments/{attachment_id}
```

#### Notifications, forms, email intake

```text
GET, POST              /api/v1/notification-channels
PUT, DELETE            /api/v1/notification-channels/{id}
GET, POST              /api/v1/notification-templates
PUT, DELETE            /api/v1/notification-templates/{id}
GET, PUT               /api/v1/me/notification-preferences
GET                    /api/v1/notifications
POST                   /api/v1/notifications/{id}/read
GET, POST              /api/v1/notification-rules
PUT, DELETE            /api/v1/notification-rules/{id}
POST                   /api/v1/notifications/dispatch
POST                   /api/v1/notifications/preview
GET, POST              /api/v1/forms
GET, PUT               /api/v1/forms/drafts
DELETE                 /api/v1/forms/drafts/{id}
GET, PATCH             /api/v1/forms/{id}
GET                    /api/v1/forms/{id}/submissions
GET, POST              /api/v1/form-request-links
POST                   /api/v1/email-intake
GET, POST              /api/v1/intake-tokens
DELETE                 /api/v1/intake-tokens/{id}
GET                    /api/v1/email-intake-log/{id}
```

#### Integrations, RMM, status monitoring, contact sync

```text
GET                    /api/v1/integrations
GET                    /api/v1/integrations/{provider}
PUT                    /api/v1/integrations/{provider}
POST                   /api/v1/integrations/{provider}/connect
POST                   /api/v1/integrations/{provider}/disconnect
GET, POST              /api/v1/rmm/connections
GET, PUT, DELETE       /api/v1/rmm/connections/{id}
POST                   /api/v1/rmm/connections/{id}/test
GET, POST              /api/v1/rmm/device-mappings
PUT, DELETE            /api/v1/rmm/device-mappings/{id}
GET, POST              /api/v1/rmm/alert-rules
PUT, DELETE            /api/v1/rmm/alert-rules/{id}
POST                   /api/v1/rmm/alerts
POST                   /api/v1/rmm/status
GET                    /api/v1/status/systems/{id}/current
GET                    /api/v1/status/companies/{company_id}/backup
GET                    /api/v1/reports/status/backup-success-rate
GET                    /api/v1/reports/status/uptime
GET                    /api/v1/integrations/contact-sync
POST                   /api/v1/integrations/contact-sync/google/authorize
POST                   /api/v1/integrations/contact-sync/google/disconnect
POST                   /api/v1/integrations/contact-sync/icloud/connect
POST                   /api/v1/integrations/contact-sync/icloud/disconnect
POST                   /api/v1/integrations/contact-sync/microsoft/authorize
POST                   /api/v1/integrations/contact-sync/microsoft/disconnect
PUT                    /api/v1/integrations/contact-sync/selection
PUT                    /api/v1/integrations/contact-sync/schedule
POST                   /api/v1/integrations/contact-sync/preview
GET, POST              /api/v1/integrations/contact-sync/runs
GET                    /api/v1/integrations/contact-sync/runs/{run_id}
POST                   /api/v1/integrations/contact-sync/runs/{run_id}/cancel
GET                    /api/v1/integrations/contact-sync/review-queue
POST                   /api/v1/integrations/contact-sync/review-queue/resolve
GET, POST              /api/v1/integrations/contact-sync/vcard/uploads
POST                   /api/v1/integrations/contact-sync/vcard/uploads/{file_id}/preview
POST                   /api/v1/integrations/contact-sync/vcard/uploads/{file_id}/import
GET                    /api/v1/contacts/contacts/{contact_id}/sync
DELETE                 /api/v1/contacts/contacts/{contact_id}/sync/locks/{field}
POST                   /api/v1/contacts/contacts/{contact_id}/sync/unlink
POST                   /api/v1/contacts/contacts/{contact_id}/sync/remove-imported-data
```

#### CRM pipeline, search, reports, dashboards

```text
GET, POST              /api/v1/crm/opportunities
GET, PUT, DELETE       /api/v1/crm/opportunities/{id}
POST                   /api/v1/crm/opportunities/{id}/close
GET                    /api/v1/search
GET                    /api/v1/reports
GET                    /api/v1/reports/dashboard
GET                    /api/v1/reports/tickets
GET                    /api/v1/reports/time
GET                    /api/v1/reports/request-types
GET                    /api/v1/reports/billing
GET                    /api/v1/reports/projects
GET                    /api/v1/reports/clients
GET                    /api/v1/reports/custom/schema
POST                   /api/v1/reports/custom
GET                    /api/v1/reports/{report}/export
GET, POST              /api/v1/reports/saved
GET, PATCH, DELETE     /api/v1/reports/saved/{id}
POST                   /api/v1/reports/saved/{id}/execute
GET, POST              /api/v1/reports/saved/{id}/schedules
GET, PATCH, DELETE     /api/v1/reports/schedules/{schedule_id}
GET, POST              /api/v1/dashboards
GET                    /api/v1/dashboards/default
GET, PATCH, DELETE     /api/v1/dashboards/{id}
GET, POST              /api/v1/dashboards/{id}/schedules
GET, PATCH, DELETE     /api/v1/dashboards/schedules/{schedule_id}
```

#### Settings, features, audit, data transfer, operator

```text
GET, PUT               /api/v1/settings
GET                    /api/v1/settings/modules
GET, PUT               /api/v1/settings/modules/{module}
GET, PUT               /api/v1/settings/email
POST                   /api/v1/settings/email/test-send
POST                   /api/v1/settings/email/verify
GET, PUT               /api/v1/settings/google-contacts-client
GET, PUT               /api/v1/settings/app-name
GET                    /api/v1/settings/{category}
GET, PUT, DELETE       /api/v1/settings/{category}/{key}
GET                    /api/v1/settings/feature-toggles
PUT                    /api/v1/settings/feature-toggles/{key}
GET                    /api/v1/audit-log
GET                    /api/v1/audit-log/export.csv
GET                    /api/v1/audit-log/entity/{entity_type}/{entity_id}
GET                    /api/v1/data/export
POST                   /api/v1/data/import
POST                   /api/v1/data/seed-demo
GET                    /api/v1/ip-enrichment
GET                    /api/v1/admin/providers/status
GET                    /api/v1/admin/providers/status.html
POST                   /api/v1/admin/providers/status/refresh
```

#### Contact portal (prefix /api/v1/contact)

```text
POST                   /api/v1/contact/auth/login
POST                   /api/v1/contact/auth/refresh
POST                   /api/v1/contact/auth/logout
POST                   /api/v1/contact/auth/set-password
POST                   /api/v1/contact/auth/login-link
POST                   /api/v1/contact/auth/login-link/redeem
GET, PUT               /api/v1/contact/auth/me
PUT                    /api/v1/contact/auth/me/password
POST                   /api/v1/contact/auth/me/mfa/setup
POST                   /api/v1/contact/auth/me/mfa/enable
POST                   /api/v1/contact/auth/me/mfa/disable
GET                    /api/v1/contact/auth/me/sessions
DELETE                 /api/v1/contact/auth/me/sessions/{session_id}
GET, PATCH             /api/v1/contact/companies/self/branding
POST                   /api/v1/contact/access-requests
GET                    /api/v1/contact/dashboard/summary
GET                    /api/v1/contact/portal/{handle}/host
GET                    /api/v1/contact/portal/{slug}/resolve-to-portal-id
GET, POST              /api/v1/contact/payment-methods
DELETE                 /api/v1/contact/payment-methods/{id}
PUT                    /api/v1/contact/payment-methods/{id}/default
PUT, DELETE            /api/v1/contact/companies/self/{asset}
```

#### Public, unauthenticated (prefix /api/v1/public, 60 requests per minute per client IP)

```text
GET                    /api/v1/public/config
GET                    /api/v1/public/tenants/{tenant_id}/logo
GET                    /api/v1/public/companies/{company_id}/{asset}
GET                    /api/v1/public/tenants/{tenant_id}/{asset}
GET                    /api/v1/public/kb/attachments/{attachment_id}
GET                    /api/v1/public/tickets/attachments/{attachment_id}
GET, POST              /api/v1/public/request-forms/{token}
GET                    /api/v1/public/contact-sync/google/callback
GET                    /api/v1/public/contact-sync/microsoft/callback
GET                    /api/v1/public/invoice-issuer/{provider}/callback
```

#### Inbound webhooks and machine endpoints (self-authenticated)

```text
POST                   /api/v1/bunyip/webhooks/account-deleted
POST                   /api/v1/bunyip/webhooks/mokosh-grant-changed
POST                   /api/v1/bunyip/oauth2/backchannel-logout
POST                   /api/v1/stripe/webhooks/{tenant_id}
POST                   /api/v1/paypal/webhooks/{tenant_id}
POST                   /api/v1/webhooks/xero
POST                   /api/v1/webhooks/quickbooks
```


Self-authenticating routes:

- `POST /api/v1/rmm/alerts` and `POST /api/v1/rmm/status`: HMAC-SHA256 of the raw body in the `X-Signature` header, compared
  in constant time against the stored connection secret; no bearer.
- `POST /api/v1/email-intake` and the intake log: tenant intake bearer token from `tenant_intake_tokens`.
- `POST /api/v1/bunyip/webhooks/*`: `X-Webhook-Signature`, hex HMAC-SHA256 of the body with `BUNYIP_WEBHOOK_SECRET`.
  Replays are idempotent.
- `POST /api/v1/bunyip/oauth2/backchannel-logout`: mounted only when the identity-provider verifier is configured;
  verifies the logout token and records the ended session; rate limited.
- `POST /api/v1/stripe/webhooks/{tenant_id}` and `/api/v1/paypal/webhooks/{tenant_id}`: the tenant's active provider
  verifies the delivery over the raw body (`Stripe-Signature` HMAC, or PayPal verification of the transmission headers)
  before parsing; a delivery from a provider that is not the tenant's active one is refused.
- `POST /api/v1/webhooks/xero` (`x-xero-signature`) and `/quickbooks` (`intuit-signature`): base64 HMAC-SHA256 over the raw
  body.

CORS: allowed methods GET, POST, PUT, DELETE, PATCH, OPTIONS; allowed request headers `Authorization`, `Content-Type`,
`Accept`, `X-Forwarded-Host`; credentials allowed; preflight cache 600 s. Allowed origins come from `CORS_ORIGIN`
(exact origins, or a scheme-locked `https://*.example.com` wildcard on the leftmost label); a malformed entry fails
startup.

### 4.2 Command line

`mokosh-server` with no argument serves. With a first argument from this list it runs the task and exits non-zero on
error:

| Subcommand | Arguments | Purpose |
|---|---|---|
| `bootstrap-infisical` | env `INFISICAL_ADMIN_EMAIL`, `INFISICAL_ADMIN_PASSWORD` (required); `INFISICAL_ADMIN_FIRST_NAME`, `INFISICAL_ADMIN_LAST_NAME`, `INFISICAL_URL`, `INFISICAL_PROJECT_NAME`, `INFISICAL_IDENTITY_NAME`, `INFISICAL_ENVIRONMENT`, `MOKOSH_ENV_FILE` | First-run setup of a secret-manager instance; writes the resulting credentials into an env file. |
| `qa-seed`, `qa-teardown` | `--tenant <uuid>` or env `MOKOSH_QA_TENANT_ID`; env `DATABASE_URL` | Load or remove the QA walkthrough dataset; refuses any tenant not marked QA. |
| `showcase-seed`, `showcase-refresh`, `showcase-teardown` | `--tenant <uuid>` or env `MOKOSH_SHOWCASE_TENANT_ID`; env `DATABASE_URL` | Create, reset or remove the showcase dataset; refuses any tenant not marked showcase. |
| `provider-status` | `--json`, `--text` | Presence matrix: every declared key per provider and which provider serves it; values are never printed. |
| `provider-set` | `--secret <NAME>`, `--from-env <VAR>`, `--json`, `--text` | Write one application-tier secret, read from the named environment variable, into the provider the deployment declares, then read it back and compare; takes effect after a restart. |
| `provider-migrate` | `--from <provider>`, `--to <provider>`, `--json`, `--text` | Copy every key the source provider holds into the target with read-back comparison; never clears the source. |
| `provider-purge` | `--provider <name>`, `--confirm`, `--json`, `--text` | Delete every key a disabled provider holds, only where the key is verified live in the serving provider; a dry run unless `--confirm`. |
| `verify-providers` | `--json`, `--text` | Boot each provider seam and report whether it serves; sends an SMTP NOOP for the email row; exits non-zero on any failure. |

`mokosh-bootstrap` (`src/bin/mokosh-bootstrap.rs`) is a second binary shipped in the image with subcommands
`bootstrap-infisical`, `qa-seed`, `qa-teardown`, `dev-seed-portal` (portal fixture tenants and contacts for development),
`normalize-company-industries` (map free-text industries onto the canonical set across tenants) and `--version`.

## 5. Data model

### 5.1 Storage and migrations

PostgreSQL. SQL migrations live in `migrations/` as `NNN_name.sql` files (starting at `002_tenants.sql`) and are embedded
into the binary with `sqlx::migrate!` and copied into the image at `/app/migrations`. They are applied at boot on the
privileged pool when `RUN_MIGRATIONS` is true. Applied migrations missing from the directory are ignored
(`set_ignore_missing(true)`). Migrations create the extensions `uuid-ossp`, `pg_trgm`, `citext` and `pgcrypto`.

Two database roles are used: `mokosh_migrator` (login, `BYPASSRLS`, owns the schema, runs DDL, migrations, bootstrap,
cross-tenant workers and the explicitly pre-authentication paths) and `mokosh_app` (login, `NOSUPERUSER NOBYPASSRLS`,
serves requests, owns nothing). Both are created idempotently at first boot from `MOKOSH_ADMIN_DATABASE_URL` when the
migrator role cannot yet log in. Each pool allows 20 connections (minimum 2), a 30 s acquire timeout, 600 s idle timeout
and 1800 s maximum lifetime.

### 5.2 Tenant isolation

Tenant-scoped tables carry `tenant_id`, enable and force row level security, and have a policy named `tenant_isolation`
comparing `tenant_id` with `current_setting('app.current_tenant')`. The setting is applied per transaction by
`begin_with_tenant`. Because `mokosh_app` does not bypass RLS, a query run without the setting sees no tenant rows.
Cross-tenant and pre-authentication reads (login, webhooks, workers) use the migrator pool.

### 5.3 Tables by domain

Tables created by the migrations (`CREATE TABLE`), grouped:

- Tenancy and identity: `tenants`, `tenant_settings`, `module_config`, `feature_toggles`, `users`, `user_sessions`,
  `api_keys`, `password_reset_tokens`, `user_oauth_identities`, `identities`, `tenant_memberships`,
  `tenant_membership_entitlements`, `platform_admins`, `teams`, `team_members`, `tenant_invitations`,
  `mokosh_bunyip_grants`, `mokosh_grant_invitations`, `login_approvals`, `user_login_devices`.
- Clients and portal: `companies`, `company_industries`, `contacts`, `contact_phones`, `contact_companies`, `sites`,
  `portal_roles`, `contact_role_assignments`, `contact_sessions`, `portal_setup_tokens`, `portal_refresh_tokens`,
  `portal_password_reset_tokens`, `portal_login_intents`, `portal_access_requests`, `portal_delegations`,
  `portal_exports`, `contact_notification_preferences`, `contact_payment_methods`.
- Contact import: `contact_sync_connections`, `contact_sync_links`, `contact_field_locks`, `contact_sync_candidates`,
  `contact_sync_oauth_states`, `contact_sync_suppressions`, `contact_sync_runs`, `contact_import_files`.
- Service desk: `tickets`, `ticket_sequences`, `ticket_queues`, `ticket_statuses`, `ticket_priorities`, `ticket_types`,
  `ticket_categories`, `ticket_notes`, `ticket_attachments`, `ticket_automation_rules`, `ticket_templates`,
  `ticket_saved_views`, `ticket_approvals`, `change_requests`, `workflow_rules`, `workflow_rule_runs`,
  `email_mailboxes`, `email_parse_rules`, `email_intake_log`, `tenant_intake_tokens`.
- SLA: `business_hours`, `holiday_calendars`, `sla_policies`, `sla_targets`, `sla_notifications`.
- Time, projects, calendar: `work_types`, `time_entries`, `time_rounding_rules`, `active_timers`, `work_day_segments`,
  `mileage_entries`, `projects`, `project_phases`, `project_types`, `task_statuses`, `tasks`, `task_dependencies`,
  `appointments`, `appointment_reminders`, `user_availability`, `time_off`, `on_call_schedules`,
  `scheduling_templates`.
- Commercial: `contracts`, `contract_items`, `contract_hour_balances`, `contract_invoice_runs`, `rate_cards`,
  `rate_card_items`, `invoices`, `invoice_lines`, `invoice_sequences`, `invoice_company_sequences`, `invoice_reminders`,
  `payments`, `payment_refunds`, `payment_terms`, `payment_gateway_configs`, `payment_webhook_deliveries`, `tax_rates`,
  `products`, `credit_notes`, `credit_note_lines`, `credit_note_sequences`, `quotes`, `quote_lines`, `quote_sequences`,
  `opportunities`, `vendors`, `expense_categories`, `bills`, `bill_lines`, `bill_payments`, `expenses`, `expense_lines`,
  `integrations`, `invoice_issuer_company_mappings`, `invoice_issuer_product_mappings`,
  `invoice_issuer_vendor_mappings`, `invoice_issuer_expense_account_mappings`, `invoice_issuer_user_mappings`,
  `invoice_issuer_oauth_states`.
- Assets and knowledge: `asset_types`, `assets`, `asset_relationships`, `asset_models`, `asset_templates`,
  `asset_tag_counters`, `configuration_items`, `credential_vault`, `asset_audit_log`, `kb_categories`, `kb_articles`,
  `kb_article_versions`, `kb_article_drafts`, `kb_article_votes`, `kb_article_attachments`, `kb_article_comments`,
  `kb_comment_mentions`.
- Forms: `form_definitions`, `form_fields`, `form_definition_drafts`, `form_submissions`, `form_request_tokens`.
- Notifications and reporting: `notification_channels`, `notification_templates`, `user_notification_preferences`,
  `notifications`, `notification_rules`, `saved_reports`, `scheduled_reports`, `saved_dashboards`,
  `scheduled_dashboards`, `audit_log`.
- Integrations and operations: `rmm_connections`, `rmm_device_mappings`, `rmm_alert_rules`, `monitored_systems`,
  `status_observations`, `secrets` (tenant secret provider rows), `app_secrets` and `app_config` (deployment-level
  provider rows), `files` (storage ledger).

### 5.4 Constraints worth knowing

- Check constraints pin enumerations in SQL as well as Rust, for example opportunity `stage` to six values with `outcome`
  set exactly when the stage is `won` or `lost`, and RMM `provider` to `tactical_rmm`, `mesh_central`, `datto`,
  `connectwise`, `ninja_rmm`. Of those only `tactical_rmm` has an adapter (section 8); the others answer with a stub that
  records an error.
- Numbering (tickets, invoices, quotes, credit notes, per-company invoices, asset tags) comes from sequence tables, not
  from application counters.
- A tombstoned user keeps its row (`deleted_at`), its email is rewritten to a `deleted-<uuid>` form so the unique
  `(tenant_id, email)` constraint does not block a re-signup.

## 6. Configuration

Configuration keys are declared once in `src/config/registry.rs` and resolved at boot into a generation; a key not
declared there cannot be read through the configuration API. The server process reads them from the process environment
(plus a `.env` file). A key has a tier: bootstrap keys are resolved once and need a restart to change; application keys
are re-resolved on a refresh. A `{NAME}_FILE` form is read by the file-based application-secret provider only. Values are
never logged; boot records name keys and providers.

### 6.1 Boot-time refusals

Outside `ENVIRONMENT` values `development`, `dev` and `test` (any other value, including an unknown one, is treated as
deployed) the server refuses to start when:

- `JWT_SECRET`, `ENCRYPTION_KEY` or `BUNYIP_WEBHOOK_SECRET` is unset or equals its built-in development value.
- `JWT_SECRET` is shorter than 32 bytes.
- `ENCRYPTION_KEY` is not exactly 64 hexadecimal characters.
- Any of `MOKOSH_DEPLOYMENT_MODE`, `MOKOSH_APP_DATABASE_URL`, `BASE_URL`, `CLIENT_ORIGIN`, `SPA_BASE_URL` is unset or
  blank. All missing variables are reported in one message with purpose and an example.
- A retired storage variable name is set (section 6.5).
- `MOKOSH_DEPLOYMENT_MODE`, `CONFIG_BACKEND`, `SECRET_BACKEND`, `APP_SECRET_BACKEND`, `STORAGE_PROVIDER`, `MAIL_PROVIDER` or
  `AUTH_PROVIDERS` holds an unrecognised value, `MAIL_PROVIDER=smtp` has no `SMTP_HOST`, or the mailer transport fails
  its boot verification.
- An application secret is declared in one provider but held only by another ("misplaced").

### 6.2 Core

| Key | Purpose |
|---|---|
| `MOKOSH_DEPLOYMENT_MODE` | `self-hosted` (default when blank) or `saas`; selects provider defaults (section 2.6). Required outside dev/test. |
| `ENVIRONMENT` | Environment name; default `development`. |
| `DATABASE_URL` | Privileged (`mokosh_migrator`) connection string; used for migrations, bootstrap and cross-tenant paths. If unset, a localhost URL is used. |
| `MOKOSH_APP_DATABASE_URL` | Request-serving (`mokosh_app`) connection string. If unset the pool falls back to `DATABASE_URL`, which makes row level security inert; required outside dev/test. |
| `MOKOSH_ADMIN_DATABASE_URL`, `MOKOSH_MIGRATOR_PASSWORD`, `MOKOSH_APP_PASSWORD` | Used only when the roles must be created at first boot. |
| `RUN_MIGRATIONS` | Run migrations at boot; default true. |
| `HOST`, `PORT` | Listen address; defaults `0.0.0.0` and `8080`. |
| `BASE_URL` | Base of platform-owned emailed links. Required outside dev/test. |
| `CLIENT_ORIGIN` | Browser origin of the client host; default for `CORS_ORIGIN` and the base for invitation and reset links. Required outside dev/test. |
| `SPA_BASE_URL` | Browser origin of the application client, base for emailed links to client-only pages; defaults to `CLIENT_ORIGIN`. Required outside dev/test. |
| `CORS_ORIGIN` | Comma-separated allowed origins; default `[CLIENT_ORIGIN]`. |
| `PUBLIC_API_BASE_URL` | This deployment's public API base, used to make tenant logos absolute in email; unset omits the logo from email. |
| `ABUSE_CONTACT_EMAIL` | Address shown in request-form emails for reporting abuse; unset omits the line. |
| `PORTAL_COOKIE_DOMAIN` | `Domain` attribute of the portal refresh cookie; unset leaves it host-scoped. |
| `MOKOSH_MAX_TENANTS` | Positive integer cap on tenant creation; blank, unparseable or non-positive means uncapped. |
| `MOKOSH_UPDATE_CHECK_URL` | Manifest URL for `/version/check`; unset disables the check. |
| `RUST_LOG` | Log filter; default `info`. |

### 6.3 Secrets and encryption

| Key | Purpose |
|---|---|
| `JWT_SECRET` | HS256 signing key for server-issued tokens (contact and staff). |
| `ENCRYPTION_KEY` | AES-256-GCM key for secrets at rest (64 hex characters; a raw 32-byte key is accepted in dev/test only). |
| `BUNYIP_WEBHOOK_SECRET` | Shared HMAC secret for identity-provider webhooks. |
| `SECRET_BACKEND` | Tenant secret provider: `database` (default) or `infisical`. |
| `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_ENVIRONMENT`, `INFISICAL_ADDRESS` | Secret-manager connection; `INFISICAL_ADDRESS` also drives the `/ready` probe (blank reports `skipped`). |
| `APP_SECRET_BACKEND` | Authoritative application-tier secret provider: `environment`, `file`, `database`, `infisical`, `bunyip`. |
| `APP_SECRETS_DIR` | Directory read by the `file` application-secret provider; unset disables that provider. |
| `BUNYIP_SECRETS_URL`, `BUNYIP_SECRETS_CLIENT_ID`, `BUNYIP_SECRETS_CLIENT_SECRET` | Connection for the `bunyip` application-secret provider. |
| `SMTP_PASSWORD`, `GOOGLE_CONTACTS_CLIENT_ID`, `GOOGLE_CONTACTS_CLIENT_SECRET`, `MICROSOFT_CONTACTS_CLIENT_ID`, `MICROSOFT_CONTACTS_CLIENT_SECRET`, `XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `XERO_WEBHOOK_KEY`, `QUICKBOOKS_CLIENT_ID`, `QUICKBOOKS_CLIENT_SECRET`, `QUICKBOOKS_VERIFIER_TOKEN` | Governed application secrets. On `saas` the Google pair is read from the `bunyip` provider by default. A half-configured client id/secret pair fails boot. |

### 6.4 Authentication and identity provider

| Key | Purpose |
|---|---|
| `AUTH_PROVIDERS` | Comma list from `local`, `bunyip`; default per profile. A provider left out is skipped as if unconfigured. |
| `OIDC_ISSUER`, `OIDC_AUDIENCE` | Enable identity-provider token verification; both required for the verifier to mount. |
| `OIDC_JWKS_CACHE_TTL_SECS`, `OIDC_LEEWAY_SECONDS` | JWKS cache lifetime (default 600) and clock leeway (default 30). |
| `OIDC_DEFAULT_TENANT_ID` | Tenant used for provider identities with no placement; defaults to a fixed default tenant id. |
| `OIDC_BACKCHANNEL_CLIENT_ID` | Expected audience client id for back-channel logout tokens. |
| `ALLOW_UNINVITED_BUNYIP_SIGNUP` | Boolean; allow a first-sight, email-verified provider identity to get a personal tenant; default false. |
| `LOGIN_APPROVAL_ENABLED` | Boolean; enable the suspicious-login approval gate; default false. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Create the first platform admin when none exists. |
| `BUNYIP_API_BASE_URL`, `BUNYIP_DIRECTORY_CLIENT_ID`, `BUNYIP_DIRECTORY_CLIENT_SECRET` | Directory lookup client for grant invitations; a partial set disables it with a warning. |
| `BUNYIP_STATUS_CLIENT_ID`, `BUNYIP_STATUS_CLIENT_SECRET` | Machine credential accepted as HTTP Basic by the JSON provider status endpoint. |
| `BUNYIP_CONFIG_URL`, `BUNYIP_CONFIG_CLIENT_ID`, `BUNYIP_CONFIG_CLIENT_SECRET`, `CONFIG_PROVIDERS`, `CONFIG_FILE_DIR`, `CONFIG_BACKEND` | Configuration provider selection and chain inputs; the server process accepts only `environment` through `CONFIG_BACKEND`. |
| `ORGANIZATIONS_ENABLED` | Boolean flag declared with defaults false (self-hosted) and true (saas); no code path reads its value. |
| `MOKOSH_SEED_TENANT_ID` | UUID of the template tenant whose configuration is copied into newly provisioned tenants; default `00000000-0000-0000-0000-000000000001`. A malformed value is a configuration error. |
| `MOKOSH_DEMO_SEED` | Truthy value enables automatic first-visit demo seeding outside `production`. |

### 6.5 Mail, storage, network

| Key | Purpose |
|---|---|
| `MAIL_PROVIDER` | `log`, `smtp` or `bunyip`; unset means `smtp` when `SMTP_HOST` is set, otherwise the profile default. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_FROM`, `SMTP_TLS` | Relay settings; `SMTP_TLS` is `implicit`, `starttls` or `none`; a username without a password is an error. A database-stored email setting, when present, overrides these and can be changed at runtime. |
| `BUNYIP_MAILER_URL`, `BUNYIP_MAILER_CLIENT_ID`, `BUNYIP_MAILER_CLIENT_SECRET` | Connection for the `bunyip` mail provider. |
| `STORAGE_PROVIDER` | `local` (default) or `s3`. |
| `STORAGE_ROOT` | Local provider root directory; default `./attachments`. |
| `STORAGE_S3_ENDPOINT`, `STORAGE_S3_BUCKET`, `STORAGE_S3_REGION`, `STORAGE_S3_PATH_STYLE`, `STORAGE_S3_ACCESS_KEY_ID`, `STORAGE_S3_SECRET_ACCESS_KEY` | S3-compatible provider settings; region defaults to `us-east-1`. |
| `STORAGE_BACKEND`, `ATTACHMENT_DIR`, `S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION`, `S3_PATH_STYLE`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | Retired names. Setting any of them refuses boot with the replacement named. |
| `ATTACHMENT_MAX_BYTES`, `KB_ATTACHMENT_MAX_BYTES`, `TENANT_LOGO_MAX_BYTES`, `BRANDING_TENANT_FAVICON_MAX_BYTES`, `BRANDING_TENANT_BACKGROUND_MAX_BYTES`, `BRANDING_COMPANY_LOGO_MAX_BYTES`, `BRANDING_COMPANY_FAVICON_MAX_BYTES`, `BRANDING_COMPANY_BACKGROUND_MAX_BYTES` | Upload size caps. Defaults: ticket attachments 25 MiB, KB attachments 5 MiB, logos 1 MiB, favicons 512 KiB, backgrounds 2 MiB. |
| `IP2LOCATION_DB_PATH` | IP2Location `.BIN` for login-country resolution; unset disables login-location alerts and the approval gate's country check. |
| `IP2PROXY_DB_PATH` | IP2Proxy `.BIN` for the admin enrichment lookup; unset disables it. |
| `TRUSTED_PROXY_CIDR` | Comma-separated CIDRs of proxies whose `X-Forwarded-For` is honoured; default loopback, RFC 1918, ULA and link-local ranges. |
| `OUTBOUND_PRIVATE_ALLOWLIST` | Hosts and CIDRs that tenant-supplied outbound URLs may reach despite being private. |
| `STRIPE_API_BASE`, `PAYPAL_API_BASE` | Override the payment API base URL (test stubs); PayPal otherwise selects its sandbox or live host from the credential. |

## 7. Security

### 7.1 Authentication and authorization

- Three credential planes with distinct JWT `typ` claims so a token cannot be replayed across planes: staff (`access`,
  `refresh`, `identity`, plus the identity provider's `at+jwt`), contact portal (`contact`, access 15 minutes, refresh
  30 days, refresh cookie `HttpOnly; Secure; SameSite=Lax; Path=/api/v1/contact/auth`), and platform admin (`platform`).
- Only access tokens are accepted as bearers; a refresh token used as a bearer is refused.
- Role checks are extractors (section 4.1). Roles are `super_admin`, `admin`, `manager`, `technician`, `dispatcher`,
  `sales`, `finance`; `RequireAdmin` admits `super_admin` and `admin`, `RequireManager` adds `manager`,
  `RequireFinance` adds `finance`.
- Passwords are hashed with Argon2id. Contact-portal passwords must be 12 to 128 characters, have a zxcvbn score of at
  least 3 and not be in a built-in common-password list.
- Password-reset, portal setup, login-approval, intake and API-key secrets are stored as hashes (portal setup and
  reset tokens also keep a SHA-256 lookup value so one row is verified rather than every candidate).
- MFA secrets are stored encrypted with `ENCRYPTION_KEY`.
- Cross-tenant access is prevented by row level security (section 5.2) in addition to service-layer scoping. Contact
  portal requests re-check tenant and contact access on every request, not only at token issue.

### 7.2 Secret handling

- Tenant integration credentials (payment gateways, RMM connections, notification channels) are
  AES-256-GCM ciphertext or live in the selected tenant secret provider; they are never returned to clients.
- Tenant data export excludes `payment_gateway_configs`, `credential_vault`, `api_keys`, `rmm_connections`, identity and
  session tables, and drops secret-looking columns from every row.
- Credential-vault reveal is a separate audited call; the company documentation view returns references only.
- `JWT_SECRET`, `ENCRYPTION_KEY` and `BUNYIP_WEBHOOK_SECRET` have development fallbacks that are refused outside
  dev/test (section 6.1).

### 7.3 Input validation and output hardening

- Request bodies are validated with `validator` derives; failures return field-level errors in the error envelope.
  String values in JSON bodies are sanitised before reaching handlers (excluding signature-verified paths).
- Upload size caps are enforced per route with `DefaultBodyLimit` sized to the configured cap.
- Outbound fetches of caller- or tenant-supplied URLs (company website probe, ticket automation `webhook` action, RMM provider)
  pass an SSRF guard that resolves the name, refuses any non-public address, and re-checks every redirect hop;
  `OUTBOUND_PRIVATE_ALLOWLIST` is the explicit exception list.
- Every response carries `Strict-Transport-Security` (1 year, includeSubDomains, preload), `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none';
  form-action 'none'` unless the handler already set the header.
- Client IP for rate limits and audit comes from `X-Forwarded-For` only when the socket peer is inside the trusted
  proxy ranges.

### 7.4 Rate limits

All limiters are in memory and per process; they do not survive a restart or coordinate across replicas.

| Scope | Limit |
|---|---|
| Staff login | 20 per minute per IP and 5 per minute per lowercased email |
| Staff forgot-password | 10 per minute per IP and 3 per minute per email |
| Password re-authentication | 10 per minute per IP and 5 per minute per account |
| Platform admin login | 20 per minute per IP and 5 per minute per email |
| Invoice pay | 20 per minute per caller and 10 per minute per invoice |
| Contact portal login intents | 20 per minute per IP |
| Request-link and invoice emails | 20 per hour per user |
| Grant invitation token lookups | 30 per minute per IP |
| `/api/v1/public/*` | 60 per minute per IP |

A limited request answers `429` with `Retry-After`.

## 8. Integrations and dependencies

| Role | System | Direction and use |
|---|---|---|
| Database | PostgreSQL | Primary store (sections 5.1, 5.2). |
| Identity provider | OIDC provider (`bunyip` in the code) | Verifies `at+jwt` bearers via JWKS; sends account-deleted, grant-changed webhooks and back-channel logout; optional directory lookup, machine-credential status reads, host-secret and mail provider endpoints. |
| Payments | Stripe, PayPal | Per-tenant checkout, saved payment methods, refunds, webhook reconciliation. |
| Accounting | Xero, QuickBooks (Intuit) | OAuth connect, delegated invoice and bill issuing, mappings, signed webhooks. |
| RMM | Tactical RMM | Device and alert sync with an adapter. `mesh_central`, `datto`, `connectwise` and `ninja_rmm` are accepted as provider names but resolve to a stub that fails with "not implemented" and records it in `last_error`. Signed alert and status ingest endpoints. |
| Contact directories | Google People, Microsoft Graph, iCloud CardDAV, vCard files | One-way import. |
| Mail | SMTP relay, or the identity provider's mailer | Outbound mail; `log` provider writes to the log only. |
| Secrets | Infisical, the identity provider's host-secret route | Optional secret providers. |
| Object storage | Local filesystem, S3-compatible store | Attachments, logos, branding assets. |
| Geo and network data | IP2Location LITE, IP2Proxy | Optional local database files. |

Third-party systems are reached over HTTPS with `reqwest` (rustls); the SMTP transport uses the platform TLS library.

## 9. Deployment and operations

- Build: `oci-build/Dockerfile` builds both binaries in a musl Rust builder image with dependencies cached in a separate
  layer, then copies `mokosh-server`, `mokosh-bootstrap`, `migrations/` and the font license into an Alpine runtime
  image. Build arguments `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE` and `SOURCE_DATE_EPOCH` feed the
  version banner and image labels. The release profile uses LTO, one codegen unit, `panic = "abort"` and stripping.
- Process: the image starts as root through `gosu-entrypoint.sh`, which can remap the app user's uid and gid from `PUID`
  and `PGID`, runs root hooks in `/etc/entrypoint.d/`, changes ownership of `DATA_DIRS` (`/app/attachments`), and drops
  to `appuser` (default uid 1001) with `gosu` before running `/app/mokosh-server`. Started as a non-root user it only
  checks that `DATA_DIRS` is writable.
- Port: 8080 is exposed; the listen port is `PORT`.
- Volumes: local object storage writes under `STORAGE_ROOT` (the image prepares `/app/attachments`); persist it when the
  `local` provider is used.
- Health: `GET /api/v1/health` returns `OK` without touching dependencies and is the image `HEALTHCHECK`
  (30 s interval, 3 s timeout). `GET /api/v1/ready` pings the database (3 s bound) and, when `INFISICAL_ADDRESS` is set,
  the secret manager's `/api/status` (1 s timeout); it answers `200` with `status: ready` or `503` with `not_ready`, and
  per-check results (`ok`, `skipped` or `error: ...`). It is sent with `Cache-Control: no-store`.
- Version: `GET /api/v1/version` returns the build's version information; the startup log prints the banner.
- Development: `Dockerfile` runs `cargo run` against sources mounted by `compose.dev.yml`, which also defines
  PostgreSQL, a local mail catcher, and optional profiles for a secret manager and an S3-compatible store.
- Repository checks: the `justfile` `check` recipe runs compile, clippy, rustfmt, migration immutability, route-consumer,
  configuration and documentation guards implemented as Nushell scripts under `scripts/`; integration tests live in
  `tests/` and browser tests in `e2e/`.

## 10. Non-functional behavior

- Logging: `tracing` text output to stdout, filtered by `RUST_LOG`. Request tracing is applied to the whole router.
  Boot logs record the hosting profile, the provider selected per capability and whether each was chosen by profile or by
  explicit configuration, the classification of each governed secret (used, missing, shadowed, misplaced), and
  warnings for declared features whose keys no provider holds. Expected token rejections (junk, expired) log at `debug`;
  identity-provider outages and misconfiguration log at `warn`.
- Errors: all error responses share one JSON envelope; a failure is never reported with a success status
  (section 2.4). Database and internal errors are mapped to server-error statuses.
- Background work: tick failures are logged and retried at the next tick; notification delivery distinguishes transient
  from permanent failures and records the state on the row.
- Concurrency: several replicas can run the dispatcher safely (`SKIP LOCKED`); rate limiters and the revoked-session
  list are per process.
- Performance bounds: database pool of 20 connections per pool; responses are gzip or brotli compressed; attachment
  downloads stream from storage instead of buffering; recurring appointments are expanded per requested range.
- Observability endpoints: `/api/v1/health`, `/api/v1/ready`, `/api/v1/version`, `/api/v1/providers` (public
  provider summary), `/api/v1/admin/providers/status` (full report, JSON or HTML) and its refresh.
