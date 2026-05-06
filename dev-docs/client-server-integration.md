# Client / server integration - server perspective

How `mokosh-server` and `mokosh-clients` fit together. Read this when
planning a feature module or wondering "is anyone actually consuming
this endpoint yet?"

A symmetric view of the same content lives at
[`mokosh-clients/dev-docs/client-server-integration.md`](../../mokosh-clients/dev-docs/client-server-integration.md).

## At a glance

- The `mokosh-clients` UI ships **18 functional surfaces** (a
  dashboard plus 14 router sections plus 3 portal screens).
- This server has real, DB-backed handlers for **4** of those
  surfaces (auth, tickets, contacts, tenants).
- The other 14 hit `stub_routes()` and return HTTP 501.
- The client currently does **zero `/api/v1/*` requests** in normal
  operation. Empirically observed via Chrome network tracking on
  2026-05-06 across `/dashboard`, `/tickets`, and
  `/portal/tickets/new`. The SPA renders mock data without ever
  contacting this server.

The implication: even the four implemented modules are not exercised
end-to-end. They have been verified by code inspection, not by a
client driving them. Until the client adds an HTTP layer, server bugs
hide.

## DTO sharing

Both repos define types under `src/modules/<module>/models.rs`. As of
2026-05-06 the four real-module trees are **byte-identical** between
this repo and `mokosh-clients`:

```
src/modules/auth/{mod,models,routes,service,middleware,bootstrap}.rs
src/modules/contacts/{mod,models,routes,service}.rs
src/modules/tenants/{mod,models,routes,service}.rs
src/modules/tickets/{mod,models,routes,service,automation}.rs
```

Each `mod.rs` uses `#[cfg(feature = "server")]` so the WASM build
omits the handler / service / middleware / bootstrap files and keeps
only the model types. This is **manual sync via copy-paste**, not a
shared crate, not codegen.

The pattern is currently in lock-step. It will silently drift the
moment one side is edited without porting. Three options:

- **(a) Shared crate.** Extract a `mokosh-types` workspace crate;
  both repos depend on it. One source of truth, zero copy. Best
  long-term answer.
- **(b) Drift CI.** Keep the copy-paste, formalize it: a CI check
  that diffs `mokosh-server/src/modules/<n>/` against
  `mokosh-clients/src/modules/<n>/` for the four shared modules and
  fails the build on non-zero. Cheapest today.
- **(c) Manual sync.** Lowest setup cost, highest drift risk over
  time. Works only as long as the team is small.

Recommendation: **(b) today, (a) when a fifth shared module is
added.**

## Section-by-section gap

Read this as "what does the client expect, and is it there?"
Sections are listed in the client's router order
(`mokosh-clients/src/lib.rs`). The "Wait-for" column is what this
repo is on the hook for.

| # | Client section | Server status (this repo) | Schema | DTOs in sync? | Wait-for | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Auth (`/login`, `/forgot-password`, `/reset-password/:token`) | real `/api/v1/auth/*` (14 endpoints) | `users`, `user_sessions`, `password_reset_tokens` | yes | F2 (rate limit), email send | P0 |
| 2 | Dashboard | no aggregate endpoint yet | covers many tables | n/a | future `/reports/dashboard` aggregate | P3 |
| 3 | Tickets list / new / detail / notes | real `/api/v1/tickets/*` (11 endpoints) but DTOs return empty status / priority / company / contact / assignee names | `tickets`, `ticket_notes`, `ticket_statuses`, etc. | yes | **F3** (DTO joins), F11 (automation) | P1 |
| 4 | Time tracking (`/time`, `/timesheets`) | 501 (placeholder) | `time_entries`, `active_timers`, `time_rounding_rules`, `work_types` | n/a | F8 (`time_tracking` module) | P1 |
| 5 | Projects (`/projects`, `/projects/:id/tasks`) | 501 | `projects`, `project_phases`, `task_statuses`, `tasks`, `task_dependencies` | n/a | `projects` module | P1 |
| 6 | Contacts + Companies | real `/api/v1/contacts/*` (16 endpoints) but `update_site` is a silent no-op | `companies`, `contacts`, `sites` | yes | **F4** (`update_site` fix) | P1 |
| 7 | Calendar / Dispatch | 501 | `appointments`, `user_availability`, `time_off`, `on_call_schedules` | n/a | `calendar` module | P2 |
| 8 | Contracts | 501 | `contracts`, `contract_items`, `contract_hour_balances`, `rate_cards`, `rate_card_items` | n/a | `contracts` module | P2 |
| 9 | Billing (invoices + payments) | 501 | `invoices`, `invoice_sequences`, `invoice_lines`, `payments`, `payment_gateway_configs`, `tax_rates` | n/a | F7 (`billing` module) | P1 |
| 10 | Assets | 501 | `asset_types`, `assets`, `asset_relationships`, `configuration_items`, `credential_vault`, `asset_audit_log` | n/a | `assets` module | P2 |
| 11 | Knowledge base | 501 | `kb_categories`, `kb_articles`, `kb_article_versions` | n/a | `knowledge_base` module | P2 |
| 12 | Reports | 501 | aggregate over many | n/a | `reports` module | P2 |
| 13 | Settings (6 sub-pages) | 501; module-config helpers exist on `tenant_service` but unrouted | `tenant_settings`, `module_config`, `rmm_*`, `notification_*` | n/a | F5 (expose module config) | P2 |
| 14 | Admin (`/admin/tenants`) | real `/api/v1/tenants/*` (7 endpoints) | `tenants`, `tenant_settings`, `module_config` | yes | nothing | P2 |
| 15 | Portal (7 routes) | all `/api/v1/portal/*` 501; client has a critical GET-leak bug to fix in parallel | `contacts` (portal identity), tickets / invoices / kb tables | n/a | **F6** (portal contact-scoped session) | **P0** |
| 16 | RMM (lives in `/settings/integrations`) | 501 | `rmm_connections`, `rmm_device_mappings`, `rmm_alert_rules` | n/a | `rmm` module | P3 |
| 17 | Notifications (bell + `/settings/notifications`) | 501 | `notification_channels`, `notification_templates`, `user_notification_preferences`, `notifications`, `notification_rules` | n/a | `notifications` module | P2 |

Sections 1, 3, 6, and 14 are wireable from the client today. Every
other section needs work in this repo first.

## Cross-cutting integration concerns

1. **No HTTP layer in client.** The client does not currently make
   requests to this server. Empirically confirmed (zero `/api/*`
   requests across three navigations on 2026-05-06). Adding an
   `api_client` module on the client side is the highest-leverage
   single move in either repo.
2. **DTO sharing via copy-paste.** See
   [DTO sharing](#dto-sharing) above.
3. **Auth bypass + mocked client = the server is never exercised
   end-to-end.** The client has a hardcoded login bypass
   ([`hooks/auth.rs:90-118`](../../mokosh-clients/src/hooks/auth.rs#L90))
   that skips the network entirely. Removing the bypass without a
   real fetch path on the client would break login. The two changes
   land together.
4. **Companies alias is dead.** The empty
   `.nest("/companies", Router::new())` at
   [`router.rs:45`](../src/api/router.rs#L45) advertises an alias
   that doesn't exist. Either remove it (and document the canonical
   `/api/v1/contacts/companies` path) or implement the alias for
   real. Clients pointing at the unprefixed path will get 404.
5. **Schema is dramatically ahead of handlers.** 71 tables defined,
   13 read or written by the four implemented modules, ~58
   unreachable over HTTP. The shape of the future is clear. Most
   of it is still cardboard.

## Recommended sequence for landing modules

To unblock the client without doing wasted work:

1. **F3 (ticket DTO joins)** + **F4 (`update_site`)** + **F1
   (`list_users`)**. These are tiny patches and they make the
   already-real endpoints actually return what the client needs.
2. **F2 (login rate limit)**. Cheap, P0.
3. **F6 (portal contact-scoped session + minimal portal endpoints)**.
   Unblocks the customer-facing surface.
4. **F7 (`billing` module read-only)**. The client has a heavy
   invoices UI with no backend.
5. **F8 (`time_tracking` module)**. Same reason; user-produced data.
6. **F5 (expose module-config endpoints)**. Unblocks `/settings/*`.

After step 6 the client has enough server surface area to wire every
section that the user actually interacts with. The remaining
modules (`projects`, `contracts`, `calendar`, `assets`,
`knowledge_base`, `reports`, `notifications`, `rmm`, `sla`,
`audit`) can be sequenced by feature urgency.

## Smoke check

The integration table is true if all three of these hold:

- **Section 3 (Tickets):** this repo's
  [`routes.rs`](../src/modules/tickets/routes.rs#L31) registers 11
  endpoints; the client at
  [`pages/tickets.rs:188-192`](../../mokosh-clients/src/pages/tickets.rs#L188)
  has a `TableRow { onclick: |_| {}, ... }` empty closure. DTOs
  come back empty per
  [`routes.rs:71`](../src/modules/tickets/routes.rs#L71).
- **Section 9 (Billing):**
  [`src/modules/billing/mod.rs`](../src/modules/billing/mod.rs) is
  one line; [`router.rs:64-65`](../src/api/router.rs#L64) maps
  `/invoices` and `/payments` to `stub_routes()`.
- **Section 15 (Portal):** [`router.rs:90-99`](../src/api/router.rs#L90)
  shows all `/portal/*` paths going through `stub_routes()`. The
  client at
  [`pages/portal.rs:269-329`](../../mokosh-clients/src/pages/portal.rs#L269)
  has a `<form>` with no `onsubmit`.

If any of those don't hold, this doc is stale - please update.
