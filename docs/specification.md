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

## 10. Build, CI and deployment

This section covers `.forgejo/workflows/`, `oci-build/`, `Dockerfile`, `compose.dev.yml`, `justfile`, `.env.example`,
`Cargo.toml`, `rust-toolchain.toml`, `.cargo/`, `.config/`, `.devcontainer/`, `renovate.json`, `.gitignore`,
`.gitmodules`, `.noseyparker-ignore.txt`, `scripts/*.nu`, and the non-test configuration and helpers under `e2e/`.
Requirements are numbered `SPEC-10.<n>` and cited at their implementing or enforcing site with a 1-2 line comment.

### 10.1 Compile and lint gate (`.forgejo/workflows/check.yml`)

- **SPEC-10.1** On every `pull_request` targeting `main`, the `check` job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_HEAVY }}`; the workflow must fail if the job exceeds its 30-minute timeout.
- **SPEC-10.2** `check.yml` must not declare a `push` trigger for `main`: re-running compile and lint after a merge gates nothing, since the pull request already covered the merge commit.
- **SPEC-10.3** The checkout step must set `fetch-depth: 0` (so migration-immutability can diff against `origin/main`) and `submodules: true` (so `common/common.just` resolves and `just --list` parses).
- **SPEC-10.4** The job must also shallow-clone `psa-systems/mokosh-apps` to path `mokosh-apps` using `secrets.FORGEJO_PAT`, for the route-consumers check.
- **SPEC-10.5** `CARGO_BUILD_JOBS` must be set to `nproc/2`, capping build parallelism at half the host's cores.
- **SPEC-10.6** The Rust build cache (`Swatinem/rust-cache@v2`) must use `shared-key: check` with `cache-on-failure: true`, matching `cache-warm.yml`'s `warm-check` job's key exactly; a mismatch means a pull request restores nothing.
- **SPEC-10.7** The job must run, in order, and fail the workflow if any exits non-zero: `just check-migration-versions`, `just check-migration-immutability`, `just check-migration-versions-against-base`, then `nu scripts/check-guarded-content-migrations.nu`, `check-no-duplicate-mail-copy.nu`, `check-pool-safety.nu`, `check-create-update-validate-parity.nu`, `check-rate-limit-helper.nu`, `check-runner-labels.nu`, `check-oci-build-cache.nu`, `check-oci-publish-tags.nu`, `check-workspace-deps.nu`, `check-env-example.nu`, `check-build-target-storage.nu`, `check-doc-recipes.nu`, `check-config-doc-paths.nu`, `config-docs.nu self-test` then `config-docs.nu check`, `check-doc-links.nu`, `check-claude-md.nu --self-test` then `check-claude-md.nu`, `cargo machete` (after installing pinned cargo-machete 0.9.2), then `check-route-consumers.nu` with env `MOKOSH_APPS_DIR=mokosh-apps`.
- **SPEC-10.8** `cargo-machete` must be installed by downloading `cargo-machete-v0.9.2-x86_64-unknown-linux-musl.tar.gz` from its GitHub release, verifying it against SHA-256 `48200087f54c55aabcd4db4af1e25742b49846c02a1b1bfa134711945b35b2e9` with `sha256sum --check --strict`, and installing to `${CARGO_HOME:-$HOME/.cargo}/bin/cargo-machete`; a checksum mismatch must fail the step.
- **SPEC-10.9** The job must run, in order, and fail on non-zero exit: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo check --workspace --all-targets`, `cargo test --workspace --lib`, `cargo test --workspace --doc`.
- **SPEC-10.10** The `secrets` job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` with a 15-minute timeout, rename an existing `~/.gitconfig` to `~/.gitconfig-disabled` before checkout, check out with `fetch-depth: 0` and `persist-credentials: false`, then invoke the `check-secrets` composite action from `psa-systems/common` with a fixed `kingfisher_excludes` path list, a `kingfisher_skip_regex`, and `noseyparker_ignore_file: .noseyparker-ignore.txt`.

### 10.2 Migration guard on merge (`.forgejo/workflows/post-merge-guards.yml`)

- **SPEC-10.11** On every `push` to `main`, the `guards` job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` with a 5-minute timeout, check out with `fetch-depth: 0` and `submodules: true`, then run `just check-migration-versions` and `just check-migration-immutability` against the merge result, failing the workflow if either exits non-zero.

### 10.3 Integration test gate (`.forgejo/workflows/integration.yml`)

- **SPEC-10.12** On every `pull_request` into `main` (never `push`), the workflow must run three jobs: `build` (compiles once), `test` (a matrix of 3 shards, `fail-fast: false`), and `summary` (`needs: test`, `if: always()`).
- **SPEC-10.13** The `build` job must run on `${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}` with a 25-minute timeout and env `SQLX_OFFLINE=true`, `RUST_BACKTRACE=1`.
- **SPEC-10.14** Before building, the job must fail with exit 1 and an `::error::` annotation if free disk space on the workspace filesystem is under 25 GB.
- **SPEC-10.15** The Rust build cache must use `shared-key: integration`, matching `cache-warm.yml`'s `warm-integration` job.
- **SPEC-10.16** `cargo-nextest` must be installed by downloading `https://get.nexte.st/0.9.145/linux`, verifying SHA-256 `32aa82416099eb12fffae9cf1a279ad201fecbd3f74826c613e32e9006b29867` via `sha256sum --check --strict`, then extracting to `${CARGO_HOME:-$HOME/.cargo}/bin`.
- **SPEC-10.17** The build step must run `cargo nextest archive --archive-file nextest-archive.tar.zst`, sampling free disk space every 5 seconds to `/tmp/disk-samples-build.txt` for the duration, and must propagate the archive command's own exit status, never the sampler's.
- **SPEC-10.18** The archive must be uploaded as artifact `nextest-archive` with `retention-days: 1` and `if-no-files-found: error`.
- **SPEC-10.19** The `test` job must run a 3-way matrix (`shard: [1, 2, 3]`) on `${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}` with `fail-fast: false` and a 20-minute per-shard timeout, each with its own `postgres:18.2-alpine3.23` service (`POSTGRES_PASSWORD=postgres`, `POSTGRES_USER=postgres`, `POSTGRES_DB=postgres`, health-checked every 5 seconds up to 20 retries).
- **SPEC-10.20** Each shard must download the `nextest-archive` artifact, install the same pinned nextest (0.9.145, SHA-256 `32aa...867`), disable Postgres durability (`fsync`, `synchronous_commit`, `full_page_writes` all off via `ALTER SYSTEM SET` plus `pg_reload_conf()`), create the DB roles the migrations grant to by running `scripts/test-db-roles.sql` with `ON_ERROR_STOP=1`, set `TMPDIR=$HOME/.nextest-tmp`, build the template database by running `cargo nextest run --archive-file nextest-archive.tar.zst --profile ci --no-capture -E 'test(/^suites::template_database::/)'`, then run `cargo nextest run --archive-file nextest-archive.tar.zst --profile ci --partition hash:${shard}/3`.
- **SPEC-10.21** The `summary` job must run on `${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}` with a 5-minute timeout, and must fail (`exit 1` with an `::error::` annotation) unless `needs.test.result == 'success'`.

### 10.4 Unsupported/scheduled integration suite (`.forgejo/workflows/integration-unsupported.yml`)

- **SPEC-10.22** The workflow must trigger only on `schedule: "0 6 * * 1"` (Monday 06:00 UTC) and `workflow_dispatch`, never on `push` or `pull_request`.
- **SPEC-10.23** The job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_HEAVY }}` with a 30-minute timeout, with its own `postgres:18.2-alpine3.23` service identical to `integration.yml`'s.
- **SPEC-10.24** The job must install the same pinned nextest (0.9.145 / SHA-256 `32aa...867`), then start MinIO for the S3 suite by pulling image digest `docker.io/bitnamilegacy/minio@sha256:451fe6858cb770cc9d0e77ba811ce287420f781c7c1b806a386f6896471a349c`, extracting `/opt/bitnami/minio/bin/minio` via `docker create` plus `docker cp`, verifying it against SHA-256 `0586fed6e33767430230d2f5bafd0d2f4ea2b844ce17025593dd7ab07f5f33c2`, and running it with `MINIO_ROOT_USER=mokosh MINIO_ROOT_PASSWORD=mokosh-ci-password` bound to `127.0.0.1:9000`, polling `/minio/health/live` for up to 30 seconds before failing loud.
- **SPEC-10.25** The step must fail immediately with an `::error::` if `uname -m` is not `x86_64` (the MinIO pin is amd64-only).
- **SPEC-10.26** The job must export `STORAGE_S3_ENDPOINT=http://127.0.0.1:9000`, `STORAGE_S3_BUCKET=mokosh-ci`, `STORAGE_S3_REGION=us-east-1`, `STORAGE_S3_PATH_STYLE=true`, `STORAGE_S3_ACCESS_KEY_ID=mokosh`, `STORAGE_S3_SECRET_ACCESS_KEY=mokosh-ci-password` to `GITHUB_ENV`.
- **SPEC-10.27** The job must disable Postgres durability and create DB roles identically to `integration.yml`, then run `cargo nextest run --profile unsupported` with no archive step.

### 10.5 End-to-end gate (`.forgejo/workflows/e2e.yml`)

- **SPEC-10.28** The workflow must trigger on `push: main`, `pull_request: main`, and `workflow_dispatch` with a required `environment` choice input (`staging` default, or `production`).
- **SPEC-10.29** All triggers must serialize under `concurrency: group: e2e-staging, cancel-in-progress: false`, so no run is ever cancelled mid-flight.
- **SPEC-10.30** The job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_HEAVY }}` with a 20-minute timeout and `defaults.run.working-directory: e2e`.
- **SPEC-10.31** Every `E2E_*` secret-backed env var must resolve to its `_PRODUCTION` secret only when `inputs.environment == 'production'`, else its `_STAGING` secret (except `E2E_OIDC_CLIENT_ID`, shared across environments with no suffix); `E2E_ENVIRONMENT` must be `production` only on an explicit production dispatch, else `staging`.
- **SPEC-10.32** Checkout must use `fetch-depth: 0`, required by `wait-for-deploy.mjs`'s `git log` walk.
- **SPEC-10.33** The job must install dependencies with `bun install --frozen-lockfile` and browsers with `bun x playwright install chromium firefox webkit`, with no separate Node setup step (the runner image ships `nodejs24`/`bun` pre-baked).
- **SPEC-10.34** The job must report `/dev/shm` free space and `fc-list` font count as warnings only, never failing the job, because `E2E / *` is intended as a required status check on `main`.
- **SPEC-10.35** On `push` or a `workflow_dispatch` with `environment=staging`, the job must run `node24 scripts/wait-for-deploy.mjs` (SHA-polling deploy-sync gate); on `pull_request` or a production dispatch, it must instead run `node24 scripts/health-check.mjs` (reachability check only); the two conditions must be mutually exclusive by event/environment.
- **SPEC-10.36** On `push`, `pull_request`, or a staging dispatch, the job must run `node24 scripts/check-e2e-bootstrapped.mjs` to set a `skip` output; the suite step must be skipped, not failed, when `steps.seeded.outputs.skip == 'true'`.
- **SPEC-10.37** The suite must run as `bun x playwright test`, adding `--grep-invert @external` only for a production dispatch.
- **SPEC-10.38** On failure, the job must upload `e2e/playwright-report/` and `e2e/test-results/` as artifact `playwright-report` with `retention-days: 14` and `if-no-files-found: ignore`.

### 10.6 Release and image publishing (`.forgejo/workflows/build-oci-image.yml`, `create-release.yml`)

- **SPEC-10.39** `build-oci-image.yml` must trigger on `push` to `main` or tag `v*` with a path filter limited to `src/**`, `crates/**`, `migrations/**`, `.cargo/**`, `Cargo.toml`, `Cargo.lock`, `oci-build/**`, `.forgejo/workflows/build-oci-image.yml`, plus `workflow_dispatch` with `dry_run` (boolean, default `true`) and `simulate_tag` (string) inputs.
- **SPEC-10.40** The `build-and-push` job must run only `if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')`, on `${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}`, with a 45-minute timeout and `permissions: contents: read, packages: write`.
- **SPEC-10.41** The publish mode must be derived from the trigger only, never `git describe`: `workflow_dispatch` resolves `dry-run`; a tag ref resolves `release`; `ref_name == main` resolves `latest`; any other ref resolves `branch` (rejected downstream unless allow-listed in `oci-build/get-tags.nu`). `dry_run` must be true unless the event is `workflow_dispatch` and `inputs.dry_run == "false"`; push events always publish for real.
- **SPEC-10.42** Resolved tags and mode must come from `nu oci-build/get-tags.nu --mode $mode --ref-name $ref_name --simulate-tag $simulate_tag --json`, writing `mode`, `train`, `tag`, `describe`, `dry_run` to `GITHUB_OUTPUT`.
- **SPEC-10.43** Build metadata env vars `MOKOSH_GIT_HASH` (`git rev-parse --short=12 HEAD`), `MOKOSH_GIT_DESCRIBE` (`git describe --tags --always --dirty`), `MOKOSH_BUILD_DATE` (ISO-8601 UTC), `SOURCE_DATE_EPOCH` (`git log -1 --pretty=%ct HEAD`) must be exported and passed as `--build-arg` to the Docker build.
- **SPEC-10.44** The buildx builder must use the `docker-container` driver, required for cache export.
- **SPEC-10.45** The image build must use `--cache-from type=gha` and, when not a dry run, `--cache-to type=gha,mode=max,ignore-error=true`; a dry run must use `--load` and skip `--push`/`--cache-to` entirely, so a simulated run never mutates the shared cache.
- **SPEC-10.46** `create-release.yml` must trigger on `pull_request_target: closed` into `main`, and its `create-release` job must run only `if: github.event.pull_request.merged == true && startsWith(github.event.pull_request.head.ref, 'release/v')`, calling the reusable workflow `https://dev.a8n.run/psa-systems/common/.forgejo/workflows/create-release.yml@main` with `runs-on: ${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` and `secrets: inherit`.

### 10.7 Cache warmup (`.forgejo/workflows/cache-warm.yml`)

- **SPEC-10.47** The workflow must trigger only on `push: main`, running `warm-check` (`shared-key: check`; `cargo clippy --all-targets -- -D warnings`, `cargo check --all-targets`, `cargo test --no-run --workspace --lib`, `cargo test --workspace --doc`) and `warm-integration` (`shared-key: integration`; `SQLX_OFFLINE=true`; archiving via `cargo nextest archive --archive-file /tmp/nextest-archive.tar.zst --workspace --tests`), so neither job runs any assertion-bearing test.
- **SPEC-10.48** `warm-check`'s `shared-key` must equal `check.yml`'s and `warm-integration`'s must equal `integration.yml`'s, or a pull-request run restores nothing from cache.

### 10.8 Dependency updates (`.forgejo/workflows/renovate.yml`, `renovate.json`)

- **SPEC-10.49** `renovate.yml` must trigger on `schedule: "0 2 * * 6"` (Saturday 02:00 UTC) and `workflow_dispatch`, calling the pinned reusable workflow at commit `f466fa87127d4c5d78e9b8d5a730bfc59ef45450` (aliased `main`) with `target_repository: ${{ github.repository }}` and secrets `RENOVATE_CI_TOKEN`, `PUBLIC_GITHUB_REPO_TOKEN`, `PSA_SYSTEMS_PRIVATE_PACKAGE_PAT`, `A8N_TOOLS_PRIVATE_PACKAGE_PAT`, `FORGEJO_PAT`.
- **SPEC-10.50** `renovate.json` must extend `local>psa-systems/common:renovate-default`, set `gitAuthor` to `renovate-bot <renovate-bot@users.noreply.dev.a8n.run>`, enable `osvVulnerabilityAlerts`, and restrict `enabledManagers` to exactly `cargo`, `docker-compose`, `dockerfile`, `github-actions`; Renovate must not open a PR for any other manager (for example npm in `e2e/`) from this config.
- **SPEC-10.51** The `packageRules` entry matching package names `rust`/`rustc` must group them under `groupName: "rust toolchain"`, separate from any other dependency grouping, so a toolchain bump never folds into a general dependency-update PR.

### 10.9 `justfile`: recipe wiring and precedence

- **SPEC-10.52** `justfile` must import `common/common.just` (a submodule vendored at `./common`) with `import 'common/common.just'` after `default` is defined, since `just` picks the default recipe by source order, never from an import; a clone that has not run `git submodule update --init` must fail to resolve the import before any recipe runs.
- **SPEC-10.53** `justfile` must set `allow-duplicate-recipes := true` so that the locally redefined recipes `default`, `dev-clean`, `ensure-env`, `check-docker`, `build-docker` and `test` (which also exist in `common/common.just`) are legal redefinitions, and the last definition in file order (this repo's own body, defined after the import) wins.
- **SPEC-10.54** `default` must run `just --list` and nothing else; invoking `just` with no recipe name must print the recipe list, never execute a recipe body.

### 10.10 `justfile`: check recipes

- **SPEC-10.55** `just check` must run exactly this recipe list, in order, as prerequisites: `check-compile check-clippy check-fmt check-migrations check-migration-immutability check-migration-versions-against-base check-guarded-content-migrations check-pool-safety check-validate-parity check-route-consumers check-mail-copy check-rate-limit-helper check-runner-labels check-oci-cache check-oci-publish-tags check-workspace-deps check-unused-deps check-env-example check-build-target-storage check-doc-recipes check-config-doc-paths check-config-docs check-doc-links check-claude-md`, and must not include `check-docker` or `test-integration`; any prerequisite's non-zero exit fails the whole recipe at that point.
- **SPEC-10.56** `check-compile` must run `cargo check --workspace --all-targets`.
- **SPEC-10.57** `check-clippy` must run `cargo clippy --workspace --all-targets -- -D warnings`, matching `check.yml` exactly so a lint failing CI also fails this local recipe.
- **SPEC-10.58** `check-fmt` must run `cargo fmt --all --check` and must not modify any file.
- **SPEC-10.59** `check-config-docs` must run `nu scripts/config-docs.nu self-test` then `nu scripts/config-docs.nu check`, in that order; either non-zero exit fails the recipe.
- **SPEC-10.60** `check-doc-links` must run `nu scripts/check-doc-links.nu`.
- **SPEC-10.61** `check-claude-md` must run `nu scripts/check-claude-md.nu --self-test` then `nu scripts/check-claude-md.nu`, in that order.
- **SPEC-10.62** `check-build-target-storage` must run `nu scripts/check-build-target-storage.nu`.
- **SPEC-10.63** `check-doc-recipes` must run `nu scripts/check-doc-recipes.nu`.
- **SPEC-10.64** `check-config-doc-paths` must run `nu scripts/check-config-doc-paths.nu`.
- **SPEC-10.65** `check-env-example` must run `nu scripts/check-env-example.nu`.
- **SPEC-10.66** `check-migrations` must run `check-migration-versions` and `check-migration-versions-against-base` as prerequisites (the former is `common/common.just`'s own recipe, invoking its own `scripts/check-migration-versions.nu` against `migrations_dir`).
- **SPEC-10.67** `check-migration-versions-against-base base_ref="origin/main"` must run `nu scripts/check-migration-versions-against-base.nu migrations {{base_ref}}`.
- **SPEC-10.68** `check-guarded-content-migrations` must run `nu scripts/check-guarded-content-migrations.nu`.
- **SPEC-10.69** `check-pool-safety` must run `nu scripts/check-pool-safety.nu`.
- **SPEC-10.70** `check-validate-parity` must run `nu scripts/check-create-update-validate-parity.nu`.
- **SPEC-10.71** `check-route-consumers` must run `nu scripts/check-route-consumers.nu`.
- **SPEC-10.72** `check-mail-copy` must run `nu scripts/check-no-duplicate-mail-copy.nu`.
- **SPEC-10.73** `check-rate-limit-helper` must run `nu scripts/check-rate-limit-helper.nu`.
- **SPEC-10.74** `check-runner-labels` must run `nu scripts/check-runner-labels.nu`.
- **SPEC-10.75** `check-oci-cache` must run `nu scripts/check-oci-build-cache.nu`.
- **SPEC-10.76** `check-oci-publish-tags` must run `nu scripts/check-oci-publish-tags.nu`.
- **SPEC-10.77** `check-workspace-deps` must run `nu scripts/check-workspace-deps.nu`.
- **SPEC-10.78** `check-unused-deps` must exit 1 with stderr `cargo-machete not installed: cargo install --locked cargo-machete` when `cargo-machete` is not on `PATH`, and otherwise run `cargo machete`.
- **SPEC-10.79** `check-docker` must build only the `builder` target stage (`--target builder`) of `oci-build/Dockerfile`, tagged `mokosh-server:check`, with build args `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE` computed the same way as the CI build (10.43); `check-docker` must not be a prerequisite of `just check` because it needs a Docker builder and network access that no `check.yml` step requires either.

### 10.11 `justfile`: dev stack recipes

- **SPEC-10.80** `ensure-env` must be a no-op if `.env` already exists and must never overwrite it. On first run it must generate, via `openssl rand -hex 24` (pg/migrator/app passwords, Infisical Postgres password, MinIO root password), `openssl rand -hex 32` (`JWT_SECRET`, `ENCRYPTION_KEY`), `openssl rand -hex 16` (`INFISICAL_ENCRYPTION_KEY`) and `openssl rand -base64 32` (`INFISICAL_AUTH_SECRET`), substitute these into the named keys and the three rebuilt `postgres://` URL lines (`DATABASE_URL`, `MOKOSH_ADMIN_DATABASE_URL`, `MOKOSH_APP_DATABASE_URL`, `INFISICAL_DB_CONNECTION_URI`) while leaving `${MOKOSH_PG_HOST_PORT}` as literal unexpanded text in those URLs, write the result to `.env`, and print `ensure-env: created .env with freshly generated self-owned secrets`; third-party credential placeholders from `.env.example` must stay blank.
- **SPEC-10.81** `dev *args` must depend on `ensure-env`, rewrite `.env` so exactly one `USER=<value>` line exists (from `whoami`, trimmed, replacing any prior `USER=` line), print `Starting the dev stack as <user>, routed at https://<user>-mokosh-api.a8n.run`, then run `docker compose --file compose.dev.yml up {{args}}`, passing trailing args through unmodified.
- **SPEC-10.82** `dev-infisical *args` must depend on `ensure-env`, set `MOKOSH_SERVER_INFISICAL_ADDRESS=http://infisical:8080` in `.env` (replacing any prior line with that key), then run `docker compose --file compose.dev.yml --profile infisical up {{args}} infisical infisical-postgres`.
- **SPEC-10.83** `dev-s3 *args` must depend on `ensure-env` and must error with `MINIO_ROOT_USER / MINIO_ROOT_PASSWORD are missing or blank in .env; copy both keys from .env.example and give the password a value (a .env generated before PMS-958 has neither)` if either key is empty or absent; otherwise it must fill, only when currently blank, exactly `STORAGE_S3_ENDPOINT=http://minio:9000`, `STORAGE_S3_BUCKET=mokosh`, `STORAGE_S3_REGION=us-east-1`, `STORAGE_S3_PATH_STYLE=true`, `STORAGE_S3_ACCESS_KEY_ID=<MINIO_ROOT_USER>`, `STORAGE_S3_SECRET_ACCESS_KEY=<MINIO_ROOT_PASSWORD>` (never `STORAGE_BACKEND`), then run `docker compose --file compose.dev.yml --profile s3 up {{args}} minio`.
- **SPEC-10.84** `down` must depend on `ensure-env` and run `docker compose --file compose.dev.yml down --remove-orphans`, preserving named volumes.
- **SPEC-10.85** `infisical-bootstrap` must depend on `ensure-env`; if `.env.infisical` exists it must parse it as `name=value` lines (skipping comments and blank lines) and inject them as environment, then run `cargo run --quiet --bin mokosh-server -- bootstrap-infisical` with that environment.
- **SPEC-10.86** `dev-seed-portal` must depend on `ensure-env` and run, inside the `server` compose service with `--no-deps`, `DATABASE_URL="$MOKOSH_ADMIN_DATABASE_URL" cargo run --quiet --bin mokosh-bootstrap -- dev-seed-portal`, idempotently.
- **SPEC-10.87** `dev-clean` must depend on `ensure-env`, run `docker compose --file compose.dev.yml down --remove-orphans`, remove exactly the named volumes `dev-mokosh-postgres-data-${USER}`, `dev-mokosh-infisical-postgres-data-${USER}`, `dev-mokosh-server-target-${USER}`, `dev-mokosh-attachments-${USER}` if present, recursively remove the local `target` directory if it exists (printing `removed target`), remove `.env` if it exists (printing `removed .env`), and finish by printing `dev-clean: done`.
- **SPEC-10.88** `dev-clean-all` must depend on and run after `dev-clean`, then remove the Docker images `mokosh-server:check` and `mokosh-server:local` if present, run `docker buildx prune --force`, and print `dev-clean-all: done`.

### 10.12 `justfile`: test recipes

- **SPEC-10.89** `test` (overriding `common`'s `test`) must run `cargo test --workspace --lib --bins`, deliberately scoped to `--lib --bins` and never the workspace's `tests/*` integration binaries, because at least 19 of those suites depend on one-process-per-file semantics a merged `tests/suites/*.rs` module would break.
- **SPEC-10.90** `ensure-test-db-roles` must depend on `ensure-env`, run `docker compose --file compose.dev.yml up --detach --wait postgres`, then exec, inside the `postgres` service, `psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1` feeding it `scripts/test-db-roles.sql` from stdin, so a `psql` error fails the recipe.
- **SPEC-10.91** `test-integration` must depend on `ensure-env` and `ensure-test-db-roles`, then run, inside the `server` compose service via `docker compose run --rm` with `SQLX_OFFLINE=true`: `cargo install --locked --version 0.9.145 cargo-nextest`, then (with `DATABASE_URL` overridden to `$MOKOSH_ADMIN_DATABASE_URL`) `cargo nextest run --profile ci --no-capture -E 'test(/^suites::template_database::/)'` before `cargo nextest run --profile ci`, in that order.
- **SPEC-10.92** `test-integration-unsupported` must depend on `ensure-env` and `ensure-test-db-roles`, run `cargo install --locked --version 0.9.145 cargo-nextest` then `DATABASE_URL="$MOKOSH_ADMIN_DATABASE_URL" cargo nextest run --profile unsupported`; the pinned nextest version must match `test-integration`'s.
- **SPEC-10.93** `verify-providers *args` must exec, inside the already-running `server` compose service, `/app/target/debug/mokosh-server verify-providers {{args}}`, passing trailing args through so `--json` selects a JSON envelope and the default (`--text`) prints an operator table.
- **SPEC-10.94** `verify-demo` must depend on `ensure-env` and `ensure-test-db-roles`, and run, inside `server` with `SQLX_OFFLINE=true` and `DATABASE_URL` overridden to `$MOKOSH_ADMIN_DATABASE_URL`, `cargo test --test seed_demo --test data_transfer -- --test-threads=4`.
- **SPEC-10.95** `test-e2e *args` must, from the `e2e/` directory, run `bun install --frozen-lockfile`, then `bun x playwright install chromium firefox webkit` (all three browsers), then `bun x playwright test {{args}}` with trailing args passed through.

### 10.13 `justfile`: build, image and release recipes

- **SPEC-10.96** `ci-stalls days="3"` must run `nu scripts/check-ci-stalls.nu {{days}}` and must not be a prerequisite of `just check`, since it needs network access and `FORGEJO_TOKEN`.
- **SPEC-10.97** `ci-log *args` must run `nu scripts/ci-job-log.nu {{args}}`, passing `--workflow`, `--sha`, `--run`, `--list` through.
- **SPEC-10.98** `ci-stalls-self-test` must run `nu scripts/check-ci-stalls.nu --self-test` and must need no network token.
- **SPEC-10.99** `config-docs` must run `nu scripts/config-docs.nu generate`.
- **SPEC-10.100** `config-since version *args` must run `nu scripts/config-docs.nu since {{version}} {{args}}`.
- **SPEC-10.101** `config-release-notes version *args` must run `nu scripts/config-docs.nu release-notes {{version}} {{args}}`.
- **SPEC-10.102** `build` must run `cargo build --release --bins`.
- **SPEC-10.103** `build-docker` must build the full (non-`--target`) `oci-build/Dockerfile` image, tagged `mokosh-server:local`, with the same three build args as `check-docker` (10.79), computed identically.
- **SPEC-10.104** `migrate-run` must run `sqlx migrate run` against `$DATABASE_URL`.
- **SPEC-10.105** `migrate-create name` must run `sqlx migrate add {{name}}`.

### 10.14 `justfile`: variables

- **SPEC-10.106** `app` must be the literal `"mokosh-server"`, used by `common`'s `release_crate` default for a release's `cargo update --package` step.
- **SPEC-10.107** `compose_service` must be `"server"`, not `common`'s default `"app"` (no compose service in this repo is named `app`).
- **SPEC-10.108** `clippy_args` must be exactly `"--workspace --all-targets -- -D warnings"`, deliberately never `--all-features`, since `check.yml` compiles only the default feature set.
- **SPEC-10.109** `compile_step` must be `"check"` (not `"build"`), and `compile_args` must be `"--workspace --all-targets"`.
- **SPEC-10.110** `test_args` must be exactly `"--workspace --lib"` for the common-driven hook path; the doc-test invocation runs only in CI, never via this variable.
- **SPEC-10.111** `compose_file` must be the literal `"compose.dev.yml"`, used by every recipe invoking `docker compose --file {{compose_file}}`.

### 10.15 Dev image (`Dockerfile`)

- **SPEC-10.112** The dev image must build `FROM ghcr.io/niceguyit/rust-builder-glibc:v1.2.0-rust1.98.1-trixie` and install `pkg-config libssl-dev curl` via apt, removing `/var/lib/apt/lists/*` afterward.
- **SPEC-10.113** The dev image must create `/app /data /config`, set `WORKDIR /app`, `EXPOSE 8080`, and run `CMD ["cargo", "run", "--bin", "mokosh-server"]`, so the compose-mounted source compiles on every container start rather than running a baked binary. The real listen port comes from `$PORT`, which `compose.dev.yml` sets from `MOKOSH_PORT`; the `EXPOSE 8080` is a documentation default only.

### 10.16 Production OCI image (`oci-build/Dockerfile`)

- **SPEC-10.114** The builder stage must build `FROM ghcr.io/niceguyit/rust-builder-musl:v1.1.0-rust1.98.1-alpine`, install `musl-dev pkgconfig openssl-dev openssl-libs-static lld`, and set `RUSTFLAGS="-C link-arg=-fuse-ld=lld"`.
- **SPEC-10.115** The builder must populate a dependency-only layer by copying only `Cargo.toml`/`Cargo.lock` and each workspace crate's own `Cargo.toml`, stubbing every crate's `src/lib.rs`/`main.rs`/`build.rs` with `fn main() {}`, running `cargo build --release --bins` against the stubs, then `cargo clean --release` the five first-party packages (`mokosh-server`, `mokosh-types`, `build-metadata`, `mokosh-test-macros`, `mokosh-test`) while keeping third-party artifacts, so a change under `src/` or `crates/*/src/` cannot invalidate this layer and the stub binary is never shipped.
- **SPEC-10.116** Build args `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE`, `SOURCE_DATE_EPOCH` must each default to `""` and be promoted to `ENV` of the same name below the dependency layer (not above it), so `build.rs` observes them without invalidating the dependency cache on every build; unset, `build.rs` falls back to `"unknown"` plus the package version.
- **SPEC-10.117** The real-source copy must land `migrations`, `build.rs`, `crates`, `src` (in that order) before the final `cargo build --release --bins`, because `sqlx::migrate!` reads `migrations/` at compile time and `build.rs` needs its own crate present.
- **SPEC-10.118** The runtime stage must be `FROM alpine:3.23` (pinned because `gosu` is only in Alpine 3.23's community repo), install `ca-certificates tzdata gosu shadow`, and create group+user `appuser` at fixed `uid:gid` 1001:1001 via `addgroup -g 1001 appuser && adduser -D -H -u 1001 -G appuser appuser`.
- **SPEC-10.119** The runtime stage must copy `mokosh-server`, `mokosh-bootstrap`, and `migrations` from the builder with `--chown=appuser:appuser`, and copy `src/pdf/fonts/OFL.txt` to `/app/licenses/NotoSans-OFL.txt`, a licence-obligation artifact nothing reads at runtime.
- **SPEC-10.120** The image must create `/app/attachments` and `chown -R appuser:appuser /app` before `ENV DATA_DIRS` is declared, so a freshly created named volume mounted over `/app/attachments` inherits `appuser` ownership instead of root's.
- **SPEC-10.121** The image must set `ENV APP_USER=appuser` and `ENV DATA_DIRS="/app/attachments"`, read by `gosu-entrypoint.sh`.
- **SPEC-10.122** The image must set OCI labels `org.opencontainers.image.description=Mokosh Server`, `...revision=${MOKOSH_GIT_HASH}`, `...version=${MOKOSH_GIT_DESCRIBE}`, `EXPOSE 8080`, and a `HEALTHCHECK` with `--interval=30s --timeout=3s --start-period=5s --retries=3` running `wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health`, failing on any non-success.
- **SPEC-10.123** `ENTRYPOINT` must be `["/usr/local/bin/gosu-entrypoint.sh", "/app/mokosh-server"]`; a runtime `user:` pin that is non-root disables the remap and chown steps in the entrypoint (10.125).

### 10.17 Shared container entrypoint (`oci-build/gosu-entrypoint.sh`)

- **SPEC-10.124** On start, the script must fail if `APP_USER` is unset, printing `entrypoint: APP_USER must be set by the image`; `DATA_DIRS` may be empty but must be set. It must exit 1 with `entrypoint: no command to run...` if invoked with zero arguments.
- **SPEC-10.125** When started as non-root: the script must skip the PUID/PGID remap, root hooks and chown; if `PUID`/`PGID` are set but do not match the running uid/gid it must exit 1 naming the mismatch; for each `DATA_DIRS` entry it must exit 1 if the directory is missing or not writable by the current user, else `exec` the given command as-is.
- **SPEC-10.126** When started as root: `PUID`/`PGID`, if set, must be numeric and non-zero (rejecting non-numeric or `0` with exit 1, "refusing to run the workload as root"); if unset, the resolved uid/gid must be the owner of the first `DATA_DIRS` entry when that owner is non-root, else default to `1001:1001`.
- **SPEC-10.127** The script must remap `$APP_USER` to the resolved uid/gid via `groupmod -o -g ... && usermod -o -u ... -g ...`, log the resolution source (`PUID`/`PGID`/owner-of-dir/default) to stderr, then run every executable in `/etc/entrypoint.d/*.sh` as root (skipping if the glob matches nothing), aborting with that hook's exit code if any hook fails.
- **SPEC-10.128** For each `DATA_DIRS` entry the script must `chown` only entries whose uid or gid differs from the resolved pair, then must `exec gosu "$APP_USER" "$@"` (user form, not `uid:gid`, so supplementary groups resolve from `/etc/group`).

### 10.18 Image tagging (`oci-build/get-tags.nu`)

- **SPEC-10.129** `main` must accept only `release|latest|branch|dry-run` for `--mode`; any other value must error `[get-tags] Unknown mode: '<mode>'. Expected release|latest|branch|dry-run.`.
- **SPEC-10.130** Mode `release` must resolve `{train: "release", version: ref_name}` and error `[get-tags] release train requires a non-empty version...` if `ref_name` is empty. Mode `latest` must resolve `{train: "latest", version: ""}`. Mode `branch` must resolve `{train: "branch", version: ref_name}`. Mode `dry-run` must resolve to `release` when `--simulate-tag` is non-empty, to `branch` when `--ref-name` is non-empty and not `"main"`, else to `latest`.
- **SPEC-10.131** `BRANCH_ALLOW_LIST` must be the single source of truth for which branches may publish; a `branch`-train version not on the list must error `[get-tags] Branch '<name>' is not on the publish allow-list ...`. It is currently empty (no feature branch publishes); `scripts/check-oci-publish-tags.nu` keeps `build-oci-image.yml`'s own branch filter in sync with it.
- **SPEC-10.132** The final `tag` must be the version string for `release`, `branch-tag(version)` (every `/` replaced with `-`) for `branch`, and the literal `latest` for `latest`; `describe` (`git describe --tags --always`) is diagnostic only and never changes the train. With `--json`, the record `{mode, train, tag, describe}` must serialize via `to json --raw`.

### 10.19 Dev stack compose (`compose.dev.yml`)

- **SPEC-10.133** The compose project name must be `dev-mokosh-${USER}` and every `container_name`/volume/network name must carry the `dev-mokosh-` prefix plus `-${USER}` suffix, so two developers on one host never collide; `USER` has no default (`${USER:?USER missing - run via just dev}`).
- **SPEC-10.134** `infisical`, `infisical-postgres`, and `valkey` must start only under compose profile `infisical`; `minio` must start only under profile `s3`; no other service is profile-gated.
- **SPEC-10.135** `postgres`, `infisical-postgres`, and `mailpit` host-published ports must bind to `127.0.0.1` only, as must `minio`'s two published ports; the `server` service must publish no host port at all, reaching ingress solely through the external `network-traefik-public` Traefik network via its `labels`.
- **SPEC-10.136** `postgres`'s `PGDATA` must be pinned to `/var/lib/postgresql/data/pgdata`, a subdirectory of the named volume mount, to avoid both the Postgres-18 default-path change and the entrypoint's refusal to `initdb` into a non-empty directory.
- **SPEC-10.137** The `server` service must build from `Dockerfile` with `context: .`, depend on `postgres` with `condition: service_healthy` and on `mailpit` with `condition: service_started`, and must not declare a `depends_on` for `infisical`, since a hard dependency on a profiled-out service makes compose reject the whole project.
- **SPEC-10.138** `CARGO_BUILD_JOBS` must default to `1` inside the `server` container, serializing rustc to avoid earlyoom SIGTERM around roughly 1.5 GB free; an operator may override it in `.env`.
- **SPEC-10.139** The `server` service's volumes must mount `./src`, `./crates`, `./Cargo.toml`, `./Cargo.lock`, `./build.rs`, `./migrations`, `./tests`, `./e2e:ro`, and `./.config` individually, plus named volumes `server-target:/app/target` and `attachments:/data/attachments`; a new top-level directory this list omits is invisible inside the dev container.
- **SPEC-10.140** `STORAGE_ROOT` must default to `/data/attachments` in the `server` environment, matching the `attachments:/data/attachments` mount point.
- **SPEC-10.141** The `server`'s `extra_hosts` must pin `${USER}-bunyip-api.a8n.run` to `${BUNYIP_OP_TRAEFIK_IP:-172.30.0.11}` so the in-container OIDC discovery fetch reaches the local Traefik with a valid certificate rather than the host's public edge.
- **SPEC-10.142** Traefik routing labels for `server` must use YAML list syntax, not map syntax, since Compose does not interpolate `${USER}` inside map keys, only inside string values.
- **SPEC-10.143** `minio`'s image must be pinned by digest `docker.io/bitnamilegacy/minio@sha256:451fe6858cb770cc9d0e77ba811ce287420f781c7c1b806a386f6896471a349c`, with its data volume mounted at `/bitnami/minio/data`, not `/data`, because the Bitnami non-root image cannot `chown` a freshly created volume mounted at `/data`.

### 10.20 Devcontainer (`.devcontainer/`)

- **SPEC-10.144** `devcontainer.json` must use image `ghcr.io/niceguyit/opensuse-dev:v0.7.0-leap-16.0`, and must run `config-devcontainer.sh dev` via `sudo su --login --command` on `postCreateCommand`, `updateContentCommand`, and `postStartCommand` alike, a JetBrains-only workaround since JetBrains does not run those hooks as the configured user.
- **SPEC-10.145** `config-devcontainer.sh` must add the `dev` user to a `docker-host` group matching the host docker socket's gid (creating the group if absent) whenever that gid is non-zero and not already present in `/etc/group`, so `dev` can reach `/var/run/docker.sock`.
- **SPEC-10.146** Under JetBrains (`/.jbdevcontainer/` present), the script must move each of `chezmoi`, `nushell`, and `bun`'s config directories under `/.jbdevcontainer/config/` on first run and replace the original path with a symlink owned by `dev:dev`, so JetBrains' use of `XDG_CONFIG_HOME`/`XDG_DATA_HOME` still persists configuration across container rebuilds.
- **SPEC-10.147** When `bun` is on `PATH`, the script must globally install `prettier`, `cspell`, `corepack`, `@anthropic-ai/claude-code`, `@tailwindcss/cli`, then run `bun update --global --latest` against every global package.

### 10.21 Rust toolchain and workspace (`Cargo.toml`, `rust-toolchain.toml`, `.cargo/config.toml`)

- **SPEC-10.148** The workspace must resolve with `resolver = "2"` and contain exactly four members: the root `mokosh-server` package, `crates/mokosh-types`, `crates/build-metadata`, `crates/mokosh-test-macros`, `crates/mokosh-test`; a member outside this list, or a missing one, breaks `cargo check --workspace` with an unresolved-path error.
- **SPEC-10.149** `rust-toolchain.toml` must pin `channel = "1.98.1"` with `components = ["clippy", "rustfmt"]`; every `cargo`/`rustfmt`/`clippy` invocation in this repo, dev container and CI alike, must use exactly this patch, so formatting and lint output are identical everywhere.
- **SPEC-10.150** A bump of the `rust-builder-glibc` or `rust-builder-musl` image tags (10.112, 10.114) must be accompanied, in the same change, by the matching `channel` bump in `rust-toolchain.toml`; drift between the pin and the image's actual rustc produces the same class of silent formatting/lint divergence the pin exists to prevent.
- **SPEC-10.151** `[workspace.dependencies]` must list only crate entries that at least one member inherits via `{ workspace = true }` (enforced by `check-workspace-deps.nu`, 10.179): `serde 1.0.229` (derive), `serde_json 1.0.154`, `uuid 1.11` (v4, v7, serde), `chrono 0.4.45` (serde), `async-trait 0.1.92`, `secrecy 0.10.3` (serde), `ipnetwork 0.20`, `lettre 0.11.23` (default features off; tokio1-native-tls, builder, smtp-transport, pool).
- **SPEC-10.152** `[profile.release]` must build with `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`; a release binary must abort rather than unwind on panic, and ship with symbols stripped.
- **SPEC-10.153** `[profile.dev]` must build with `debug = 0` and `codegen-units = 256` (not rustc's default `debug = 2`), to keep rustc's peak RSS under the OOM threshold of memory-constrained dev containers, leaving `overflow-checks` and `debug-assertions` at their profile defaults (on); `[profile.dev.package."*"]` must set `opt-level = 3` for every dependency crate, so only the root crate itself builds unoptimized.
- **SPEC-10.154** `.cargo/config.toml` must set `[net] git-fetch-with-cli = true`, so a `git`-dependency fetch (the `dunite-*` crates, pinned by `rev`) uses the system git CLI and its configured credential helper against the private `https://dev.a8n.run/psa-systems/dunite` repo, instead of libgit2, which can fail to authenticate against a private Forgejo remote.

### 10.22 Test runner configuration (`.config/nextest.toml`)

- **SPEC-10.155** `[profile.ci].default-filter` must read exactly `'not (test(/^suites::s3_storage::/) or test(/^suites::google_client_from_infisical::/))'`, character-for-character the negation of `[profile.unsupported]`'s filter `'(test(/^suites::s3_storage::/) or test(/^suites::google_client_from_infisical::/))'`.
- **SPEC-10.156** `cargo nextest run --profile ci` must still compile `tests/suites/s3_storage.rs` and `tests/suites/google_client_from_infisical.rs` into the one test binary on every pull request (a compile break in either fails the PR job) while never executing their cases; those suites run only via `[profile.unsupported]`, invoked weekly by `integration-unsupported.yml` (10.22-10.27) and locally by `just test-integration-unsupported` (10.92).
- **SPEC-10.157** `[profile.ci]` must run with `test-threads = 12` and `fail-fast = false`.
- **SPEC-10.158** `[profile.ci.slow-timeout]` must mark a case slow after `period = "60s"` and send it SIGTERM after `terminate-after = 3` consecutive periods (180s total), continuing the rest of the run rather than stalling the whole job.
- **SPEC-10.159** The override `[[profile.ci.overrides]]` for `filter = 'test(health_p99_does_not_regress_under_concurrent_argon2_burst)'` must set `threads-required = "num-test-threads"` and `retries = 2`; no other test in `[profile.ci]` is retried.
- **SPEC-10.160** `[profile.unsupported]` must `inherit = "ci"` (same slow-timeout, fail-fast, thread budget) and override only `default-filter`, plus set `failure-output = "immediate-final"` so a failing case in the weekly run prints its output without a local re-run.

### 10.23 Repo hygiene (`.gitignore`, `.gitmodules`)

- **SPEC-10.161** `.gitmodules` must declare submodule `common` at path `common`, url `https://dev.a8n.run/psa-systems/common.git`; a fresh clone must run `git submodule update --init` before `pre-commit`, `pre-push`, `install-hooks` or `create-release` resolve, since those recipes are implemented in the `common` submodule.
- **SPEC-10.162** `.gitignore` must exclude every `.env*` file except `.env.example` (`.env*` then `!.env.example`), so a generated `.env` with live secrets is never committed while the template always is.
- **SPEC-10.163** `.gitignore` must exclude `/secrets/` (generated OIDC signing keys), `/gen/` (build output), `/assets/styles.css` (Tailwind-generated CSS), `data/` (the dev Postgres bind-mount directory), `.claude/` (agent scratch/config), `For AI/` (local-only AI scratch context), and `/attachments/` (the default local-storage root for a bare `cargo run` or a test).

### 10.24 Secret-scan exemptions (`.noseyparker-ignore.txt`)

- **SPEC-10.164** `.noseyparker-ignore.txt` must list only individual file/directory paths, never a widened parent glob, each with a comment stating why its matches are not real secrets, and the comments must not quote the matched fixture strings themselves, since quoting would re-trigger the scanner on the ignore file itself.
- **SPEC-10.165** A real secret committed under any exempted path must be treated as the same incident class the scanner exists to catch on a clean path; the exemption is scoped to known-safe fixtures, never a blanket allowance for the listed paths.

### 10.25 Environment variable registry file (`.env.example`)

- **SPEC-10.166** `.env.example` must hold, as a comment-only key with an empty or documented-default value, every environment variable the config registry reads, checked by `check-env-example.nu` (10.189-10.193). Operators must not copy it to `.env` by hand; `ensure-env` (10.80) generates `.env` from it once per clone and fills every self-owned secret with a strong random value via `openssl rand`, so no placeholder password ever reaches a running `.env`.
- **SPEC-10.167** `MOKOSH_PG_HOST_PORT` (default `5433`) must be the single place the host-published Postgres port is written; `DATABASE_URL`, `MOKOSH_ADMIN_DATABASE_URL`, and `MOKOSH_APP_DATABASE_URL`'s host forms must interpolate it rather than repeat the literal, so resolving a port collision between two checkouts on one host cannot leave a host-side tool migrating a different checkout's database.
- **SPEC-10.168** `MOKOSH_APP_DATABASE_URL` must be the `mokosh_app` role's URL; if unset the server falls back to `DATABASE_URL` (`mokosh_migrator`, bypassing row-level security), which makes every `tenant_isolation` policy inert for request-serving connections. Outside `development`/`dev`/`test` `ENVIRONMENT` values, the server must refuse to boot if `MOKOSH_APP_DATABASE_URL` is unset.

### 10.26 CI gate scripts: migrations, pool safety, validate parity, mail copy

- **SPEC-10.169** `check-guarded-content-migrations.nu` must check only `migrations/*.sql` files whose numeric filename prefix is strictly greater than `209`; for such a file whose `UPDATE` matches `AND\s+<col>\s*(=|LIKE)\s*'` for any of `subject`, `body_text`, `body_html`, `name`, `description`, the file must also contain the literal `GET DIAGNOSTICS`, or the script exits 1 naming the file and the missing assertion; migrations numbered 209 or below are exempt unconditionally.
- **SPEC-10.170** `check-migration-versions-against-base.nu migrations_dir base_ref` must union migration filenames from `base_ref` (default `origin/main`, via `git ls-tree -r --name-only`) and the current `migrations_dir` on disk, group them by leading numeric prefix, and exit 1 listing every prefix shared by two or more distinct filenames as a post-merge collision.
- **SPEC-10.171** `check-pool-safety.nu` must scan every `src/**/*.rs` file except `src/db/pool.rs` for a non-comment line containing `.pool()` that is not a `migrator_pool` call; for each, it must look back up to 8 lines, and if none contain the substring `SAFETY (PMS-285`, record it as a violation and exit 1.
- **SPEC-10.172** `check-create-update-validate-parity.nu` must pair every `Create*Request`/`Upsert*Request` struct with its `Update*Request`/`Patch*Request` counterpart by stripped struct name; for each same-named field present on both sides, the normalized `#[validate(...)]` attribute text must be identical unless the pair-and-field is listed in the script's `ALLOWED` constant (currently empty); any mismatch, or a stale `ALLOWED` entry whose two sides no longer differ, exits 1.
- **SPEC-10.173** `check-no-duplicate-mail-copy.nu` must fail if any of the 8 seeded template phrases in its `PHRASES` constant (for example `"Welcome to {{app_name}}"`) appears as a substring anywhere under `src/`, and must separately fail unless the literal sentence `"has added an update to ticket"` appears verbatim in both `migrations/148_restore_ticket_note_org_identity.sql` and `src/modules/tickets/service.rs`.

### 10.27 CI gate scripts: rate limiting, route consumers, runner labels

- **SPEC-10.174** `check-rate-limit-helper.nu` must scan every `src/**/*.rs` file and fail if, outside `src/utils/error.rs`, a non-comment line contains `TOO_MANY_REQUESTS` or `AppError::RateLimited`, and must fail (even inside `src/utils/error.rs`) on any line containing the literal `let _ = retry_after`.
- **SPEC-10.175** `check-route-consumers.nu` must scan `src/modules/*/*.rs` for `.route("<path>", ...)` literals (with any `#[cfg(test)]` module stripped first); a route is exempt if every static path segment appears, delimiter-bounded, in `$MOKOSH_APPS_DIR/src/**/*.rs` (default `../mokosh-apps`), or if its own file carries a `//`-comment containing both `parity record` and a `YYYY-MM-DD` date and a separate comment naming that exact route literal; under CI (`$CI` set) a missing client checkout is a hard failure, else the check is skipped.
- **SPEC-10.176** For every job in every `.forgejo/workflows/*.yml` file, `check-runner-labels.nu` must fail a step that installs a toolchain package (`gcc`, `binutils`, `glibc-devel`, `libopenssl-devel`, `build-essential`) via a package manager at run time instead of requesting the dev image; must fail a job that runs `cargo ` natively without `RUNS_ON_OPENSUSE_BASE_HEAVY` in its `runs-on:`; and must fail any `runs-on:` line with no immediately preceding comment justifying its label.

### 10.28 CI gate scripts: OCI cache and publish-tag parity, workspace dependencies

- **SPEC-10.177** `check-oci-build-cache.nu` must select every `.forgejo/workflows/*.yml` file containing `docker buildx build`; after stripping `#`-comments, each must contain `--driver docker-container`, `crazy-max/ghaction-github-runtime@v3`, `cache_from = "type=gha"`, `cache_to = "type=gha,mode=max,ignore-error=true"`, `--cache-from`, `--cache-to`, and must contain none of `type=inline`, `type=registry`, `:buildcache`; any violation exits 1.
- **SPEC-10.178** `check-oci-publish-tags.nu` must verify `build-oci-image.yml`'s `on.push.branches` equals `["main"]` plus `oci-build/get-tags.nu`'s `BRANCH_ALLOW_LIST`, the `build-and-push` job's `if:` guard starts with `github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')`, `check.yml`'s `on.pull_request.branches` includes `main` and its `on.push.branches` includes every allow-listed branch, and that `get-tags`'s own mode resolution and `branch-tag` (slash-to-hyphen) behave as specified in 10.129-10.132; a branch not on the allow-list must raise, never resolve a tag.
- **SPEC-10.179** `check-workspace-deps.nu` must fail when a `[workspace.dependencies]` entry has no workspace member that inherits it via `workspace = true`, and must fail when a member declares a dependency already in `[workspace.dependencies]` without `workspace = true` (its own pin shadowing the shared one); an unresolvable `workspace.members` manifest path exits 1 immediately.

### 10.29 CI gate scripts: documentation and configuration consistency

- **SPEC-10.180** `check-doc-links.nu` must resolve every Markdown link, image, reference-definition, and HTML `href`/`src` target in every `git ls-files "*.md"` file (skipping anchors, protocol-relative and scheme URLs, fenced code, and HTML comments), root-relative for a leading `/` and else relative to the containing file; any target that does not resolve on disk exits 1 naming `<file>:<line>`.
- **SPEC-10.181** `check-doc-recipes.nu` must check a fixed set of docs (`README.md`, `docs/README.md`, `docs/quickstart.md`, `docs/architecture.md`, `docs/binaries.md`, `docs/configuration.md`, `docs/recipes.md`, `docs/invariants/ci-release.md`, `docs/invariants/config-providers.md`) for every `just <recipe>` invocation and fail if the named recipe is absent from the union of `justfile`'s non-`[private]` recipes and `just --summary`'s resolved (imported) recipes; a missing submodule import failure must direct the operator to `git submodule update --init`.
- **SPEC-10.182** `check-config-doc-paths.nu` must scan `.env.example`, `compose.dev.yml`, and `justfile` for bare `docs/...`-shaped path references and exit 1 listing any that do not resolve on disk.
- **SPEC-10.183** `check-claude-md.nu` must exit 1 when `CLAUDE.md` exceeds `20000` UTF-8 bytes, when any non-fenced line exceeds `400` characters, or when a `](docs/...)` link's target or `#anchor` does not resolve; it must name `CLAUDE.md:<line>` for any violation.
- **SPEC-10.184** `check-build-target-storage.nu` must resolve cargo's target directory in cargo's own precedence (`CARGO_TARGET_DIR`, then `CARGO_BUILD_TARGET_DIR`, then `.cargo/config.toml`'s `build.target-dir`, then `<repo>/target`), determine its filesystem type via `stat --file-system --format=%T`, and exit 1 when that type is `tmpfs` or `ramfs` unless `MOKOSH_ALLOW_TMPFS_TARGET` is `1`/`true`/`yes`.
- **SPEC-10.185** `config-docs.nu check` must fail when the registry/`variables.toml` catalog has a duplicate variable name, a malformed `since`/`required_since`/`deprecated.release`/`removed.release` value, or a `required_since` without `required: true` at a release not after `since`; when any discovered env-var read in `src/**/*.rs` or `crates/**/*.rs` is absent from the registry, `variables.toml`, and the `NOT_SERVER_CONFIG` exemption list; when `docs/configuration.md`'s `## All variables` table disagrees with the catalog on `Required`/`Added in`, is malformed, or a variable has zero or more than one row; or when the generated `Recently added` block (between its fixed marker comments) is missing, out of order, or disagrees with the computed changelog for the covered release window.
- **SPEC-10.186** `config-docs.nu generate` must rewrite only the text between the `Recently added` marker lines and the `## All variables` table rows, and running it twice in a row must be idempotent (byte-identical the second time).
- **SPEC-10.187** `config-docs.nu since <version>` must print one row per catalog change released strictly after `<version>` (labelled `WON'T START`, `FEATURE OFF: <feature>`, or blank), sorted by release then breaking-level then required-first then name, or print exactly `No configuration changes after <version>.` when there are none.
- **SPEC-10.188** A registry entry whose `required` flag becomes true in the same release it was added (other than the `v0.1.0` baseline) must have a matching `[[change]]` record naming an `issue` (`^[A-Z]+-\d+$`) and a non-empty `action`, or the catalog build fails; a `[[change]]` with `breaking: "feature-off"` must set a non-empty `feature`, or the catalog build fails.

### 10.30 CI gate scripts: environment-variable parity

- **SPEC-10.189** `check-env-example.nu` must union env-var names read by code (`declare_keys!` entries in `src/config/registry.rs`, plus every `env::var`/`env::var_os`/`require_env`/`required_env`/`parse_tenant_arg_env` call site and const-aliased name across `src/**/*.rs` and `crates/**/*.rs`) into one `CODE` set.
- **SPEC-10.190** Every `CODE` name must have a key in `.env.example` (including a commented-out `# NAME=` line) unless listed in `CODE_NOT_IN_TEMPLATE`, and must appear in `compose.dev.yml`'s `services.server.environment` map unless listed in `CODE_NOT_IN_COMPOSE`; a missing entry exits 1 naming it.
- **SPEC-10.191** Every `.env.example` key must be read by code or interpolated (`${NAME`) in `compose.dev.yml` unless listed in `TEMPLATE_UNREAD`; an unread key exits 1 naming it dead.
- **SPEC-10.192** A stale `CODE_NOT_IN_TEMPLATE`, `CODE_NOT_IN_COMPOSE`, or `TEMPLATE_UNREAD` entry, one whose excused asymmetry no longer holds, must itself exit 1 naming the entry to delete.

### 10.31 Operational and diagnostic scripts

- **SPEC-10.193** `audit-portal-no-credential.nu` must error `DATABASE_URL is required (point it at the target deployment).` when `DATABASE_URL` is unset, otherwise query `contacts` for rows with `is_portal_user = TRUE AND portal_password_hash IS NULL`, print a per-row and per-tenant summary, and print a `WARNING:` line when any row's age exceeds 7 days. This script is a manual survey tool with no `just` wrapper and no CI invocation.
- **SPEC-10.194** `check-ci-stalls.nu days="3"` must read each workflow job's `timeout-minutes` from `.forgejo/workflows/*.yml` (never a value hardcoded in the script), exit 1 if `FORGEJO_TOKEN` is unset, fetch Forgejo actions runs from the last `days` days and compare each run's wall-clock time against its workflow's bound, and exit 1 naming every run that outlived its bound; a workflow with no `timeout-minutes` on any job is excluded from judgement, never counted as passing.
- **SPEC-10.195** `ci-job-log.nu` must resolve a target run from `--run <id>`, else the 50 most recent runs filtered by `--workflow`/`--sha`/failure status (newest match wins), then fetch and print that run's first failed job's log (or the first job overall if none failed) by calling the Forgejo actions API with a token read from `~/.local/share/forgejo-cli/keys.json`; `--list` must print the candidate run table without fetching a log.

### 10.32 E2E: environment resolution and auth state

- **SPEC-10.196** `e2e/lib/env.ts` must load `e2e/.env` via dotenv with `override: false` (a real environment variable always wins), and `required(name)` must throw `Missing required env var ${name}...` when the variable is unset or blank after trimming.
- **SPEC-10.197** `E2E_BASE_URL` must be required with no hardcoded fallback; `apiBaseURL` must resolve to `E2E_API_BASE_URL` if set, else `api.` prepended to the base URL's hostname, else the base URL itself when that hostname already starts with `api.` or fails to parse; `opBaseURL` must resolve to `E2E_OP_BASE_URL` if set, else fall back to `apiBaseURL`.
- **SPEC-10.198** `E2E_EMAIL`, `E2E_PASSWORD`, `E2E_TENANT_ID`, `E2E_OIDC_CLIENT_ID`, `E2E_OIDC_REDIRECT_URI`, `E2E_TOTP_SECRET` must each be required; `E2E_FOREIGN_COMPANY_ID` must be optional; `E2E_ENVIRONMENT` must default to `staging` when unset; `preflightRequiredEnv()` must collect every missing required variable into one thrown error rather than failing on the first.
- **SPEC-10.199** The bearer token must be read from `e2e/.auth/token.txt`, OP session cookies from `e2e/.auth/op-state.json`, and the foreign-company canary id from `e2e/.auth/foreign-company.txt`; each reader must throw when its file is absent or its content is empty/malformed, and the last-used TOTP step must persist to `e2e/.auth/totp-last-step` so a cross-process run never resubmits a code for a step bunyip already saw.

### 10.33 E2E: Playwright configuration

- **SPEC-10.200** The suite must run with `fullyParallel: false` and `workers: 1` (serial), since tests share one tenant and bearer token; `forbidOnly` must be true, and `retries` must be 1, only when `process.env.CI` is set (else `false`/`0`).
- **SPEC-10.201** The global test timeout must be 60000ms and `expect.timeout` 15000ms; `globalTeardown` must run `./global.teardown.ts` after every run regardless of outcome; reporters must be `list` plus an `html` reporter that never auto-opens.
- **SPEC-10.202** On failure, `trace`, `screenshot`, and `video` must each be retained/captured only on failure (`retain-on-failure` / `only-on-failure`).
- **SPEC-10.203** The `preflight` project must have no dependencies and run first; `setup` must run in Firefox, depend on `preflight`, and resolve `env.baseURL`; `chromium`/`firefox`/`webkit` projects must each run `(auth|form-validation).spec.ts`, depend on `preflight`, and use `env.baseURL` (`chromium` additionally passing `--disable-dev-shm-usage`); `ui-selectors` must run only in Firefox, depending on `setup`; `api` must depend on `setup` and use `env.apiBaseURL`, never `env.baseURL`; `guard` must depend on `preflight` only.

### 10.34 E2E: login helper and request fixtures

- **SPEC-10.204** `loginViaSpa` must retry at most 4 times total, only on a rate-limit rejection (parsed backoff, capped at 60000ms), a `no-form` outcome (backoff 3000ms), or an `unclear` outcome, and must fail fast with no retry on a definite credential rejection.
- **SPEC-10.205** When post-credential navigation lands on `/login/(2fa|mfa)`, a TOTP step must be filled: the code must be generated only when at least 5 seconds remain in the current 30-second step, must wait for a step later than the last one this run used, and must retry with a fresh code at most twice before falling back to a manual submit click; on `/oauth2/consent`, the helper must click the allow/authorize/approve control to persist the grant.
- **SPEC-10.206** `expectAuthenticated`/`expectAnonymous` must assert `GET <tickets>?per_page=1` returns 200 when authenticated and 401 or 403 when not; `expectAtLoginScreen` must poll the page URL for up to 30000ms until it matches `/^\/login(\/|$)/`.
- **SPEC-10.207** The default `test` fixture must attach `Authorization: Bearer <token>` (from the token file) to every request context; the `oidcTest` fixture must replay the OP cookie storage state against `opBaseURL` and must never attach a bearer header.

### 10.35 E2E: test data tagging, factories and teardown

- **SPEC-10.208** Every created record's run suffix must have the shape `e2e-<epochMs>-<runId>-<n>`, where `runId` resolves from `GITEA_RUN_ID`, else `GITHUB_RUN_ID`, else `E2E_RUN_ID`, else the process start timestamp, sanitized and truncated to 24 characters; `isStale(name)` must consider a record stale only once its embedded epoch is more than 24 hours old.
- **SPEC-10.209** `createCompany`/`createContact` must assert a 200 response with a truthy `id`; `enableModule` must `PUT` `{is_enabled: true}` to the module's settings route and assert success, so a 403 (missing admin privilege) surfaces as a test failure rather than being swallowed.
- **SPEC-10.210** `global.teardown.ts` must throw when the bearer token file is absent (rather than silently skipping cleanup), page every list endpoint at the server's max page size (treating a 404 as an empty, disabled module), sweep a fixed, ordered list of 23 resource kinds (children before the parents that refuse deletion while referenced, companies last) deleting any record this run owns or that is more than 24 hours stale, and throw one aggregated error naming every collected failure after the full sweep completes.

### 10.36 E2E: deploy-readiness scripts, package and TypeScript configuration

- **SPEC-10.211** `check-e2e-bootstrapped.mjs` must probe the OP's `/e2e-bootstrapped` endpoint with a 15000ms timeout and set the `skip=true` output only when the JSON body is exactly `{bootstrapped: false}`; any non-2xx, network error, or parse failure must fall through to running the suite.
- **SPEC-10.212** `health-check.mjs` must `GET <apiBaseURL>/api/v1/health` once with a 30000ms timeout, exiting 0 on an ok response and 1 otherwise.
- **SPEC-10.213** `wait-for-deploy.mjs` must resolve the expected SHA by walking `git log` back to the most recent commit touching one of the fixed build-trigger paths (`src`, `crates`, `migrations`, `.cargo`, `Cargo.toml`, `Cargo.lock`, `oci-build`, `.forgejo/workflows/build-oci-image.yml`, kept in lock-step with `build-oci-image.yml`'s own path filter, 10.39), self-healing with `git fetch --unshallow` then `git fetch --refetch` if the walk finds nothing, then poll `GET <apiBaseURL>/api/v1/version` every 15000ms for up to 600000ms until `body.git_hash` prefix-matches; on total resolution failure it must warn and exit 0 rather than fail the job.
- **SPEC-10.214** The suite must run under `bun` per the committed `bun.lock`, never `npm ci`; TypeScript compilation must target `ES2022`/`ESNext` modules with `strict: true` and `noEmit: true`; `node_modules/`, `.auth/`, `playwright-report/`, `blob-report/`, `test-results/`, `playwright/.cache/`, and `.env` must never be committed under `e2e/`.
