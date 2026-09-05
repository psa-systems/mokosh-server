# Contact-plane cross-Company scope audit (MAPPS-633)

Every HTTP handler a portal contact (JWT `typ: "contact"`) can reach
must scope its response to the caller's own `session.company_id`.
Two existing regression suites already lock this promise:

- [`tests/contact_scope.rs`](../../tests/contact_scope.rs) — tickets
  (create / list / detail-foreign / add-note redaction), invoices
  (list scoped, detail cross-tenant 404, staff non-finance still
  403), quotes (accept flips, accept-foreign 404, without-cap 403,
  staff-accept-endpoint 403), the CRM blocks (staff-only 401 for
  contact bearers), plus a stale-JWT cap re-check.
- [`tests/contact_scope_expanded.rs`](../../tests/contact_scope_expanded.rs)
  — contracts, assets, projects, dashboard summary, PUT /auth/me.

The audit that produced this doc walked every handler enumerated
below and confirmed those two files cover every mutating + reading
contact-plane endpoint that returns row data. If you add a new
endpoint, extend one of these files.

## Rules

- **SCOPED**: handler force-sets `filter.company_id = session.company_id`
  on the list path, OR refuses (404 - stay enumeration-resistant) when
  the returned row's `company_id != session.company_id` on the detail
  path, OR the endpoint only ever returns the caller's own data.
- **N/A**: auth / session lifecycle (login, refresh, logout, set +
  reset + forgot password), the public `/host` and
  `/resolve-to-portal-id` hooks, and any endpoint that never returns
  row data.
- **UNSCOPED**: the contact branch runs a query with the caller's
  filter unchanged, OR a detail response hands out a row without
  verifying its company. If any handler ever lands here, the fix is
  the handler; do NOT paper over it with client-side filtering. Add
  a specific regression test at the same time.

## `/api/v1/contact/*` (`RequireContactAuth`)

| method path | handler | verdict |
|---|---|---|
| POST /auth/forgot-password | `forgot_password` | N/A |
| POST /auth/login | `login` | N/A |
| POST /auth/login-link | `request_login_link` | N/A |
| POST /auth/login-link/redeem | `redeem_login_link` | N/A |
| POST /auth/login-link/select | `select_login_candidate` | N/A |
| POST /auth/logout | `logout` | N/A |
| GET  /auth/me | `me` | SCOPED (own profile) |
| PUT  /auth/me | `update_me` | SCOPED (own profile, DB cap re-check) |
| POST /auth/refresh | `refresh` | N/A |
| POST /auth/reset-password | `reset_password` | N/A |
| POST /auth/set-password | `set_password` | N/A |
| GET  /companies/self/branding | `get_own_company_branding` | SCOPED (`session.company_id`) |
| PATCH /companies/self/branding | `update_own_company_branding` | SCOPED (`session.company_id`) |
| PUT  /companies/self/{asset} | `contact_upload_asset` | SCOPED (`AssetScope::Company(session.company_id)`) |
| DELETE /companies/self/{asset} | `contact_delete_asset` | SCOPED |
| GET  /dashboard/summary | `dashboard_summary` | SCOPED |
| GET  /portal/{handle}/host | `portal_host` | N/A (public host hint) |
| GET  /portal/{slug}/resolve-to-portal-id | `resolve_slug_to_portal_id` | N/A |

## `/api/v1/*` dual-plane (`RequireCallerContext`)

| method path | handler | verdict |
|---|---|---|
| GET  /assets | `list_assets` | SCOPED (force-set `filter.company_id`) |
| GET  /assets/{id} | `get_asset` | SCOPED (404 on foreign) |
| POST /assets/{id}/report-issue | `report_asset_issue` | SCOPED (portal uses `asset.company_id`) |
| GET  /contracts | `list_contracts` | SCOPED |
| GET  /contracts/{id} | `get_contract` | SCOPED |
| GET  /invoices | `list_invoices` | SCOPED |
| GET  /invoices/{id} | `get_invoice` | SCOPED |
| GET  /invoices/{id}/pdf | `get_invoice_pdf` | SCOPED (501 body, gates first) |
| GET  /projects | `list_projects` | SCOPED (NULL house projects implicitly excluded) |
| GET  /projects/{id} | `get_project` | SCOPED |
| GET  /quotes | `list_quotes` | SCOPED (`list_quotes_for_company`: own company AND issued statuses only, PMS-1060) |
| GET  /quotes/{id} | `get_quote` | SCOPED (`get_quote_for_company`: 404 on foreign OR un-issued, PMS-1060) |
| GET  /quotes/{id}/pdf | `get_quote_pdf` | SCOPED (same read as `get_quote`, PMS-1060; 501 body, gates first) |
| POST /quotes/{id}/accept | `accept_quote` | SCOPED |
| POST /quotes/{id}/decline | `decline_quote` | SCOPED |
| GET  /tickets | `list_tickets` | SCOPED |
| POST /tickets | `create_ticket` | SCOPED (portal pins `session.company_id` + `session.id`) |
| GET  /tickets/{id} | `get_ticket` | SCOPED |
| PATCH /tickets/{id} | `patch_ticket` | SCOPED + reporter-only |
| POST /tickets/{id}/approvals/request | `request_approval_on_ticket` | SCOPED |
| POST /tickets/{id}/attachments | `portal_attach_file` | SCOPED |
| GET  /tickets/{id}/notes | `get_ticket_notes` | SCOPED (public notes only) |
| POST /tickets/{id}/notes | `add_note` | SCOPED |
| POST /tickets/{id}/reopen | `reopen_ticket` | SCOPED |

## Suspected gaps

None. Every contact-reachable handler is scoped.

## Confirmations for the reported concern

The report that triggered this audit ("Company B sees Company A's
tickets, all client portals share the same passwords / same data") is
NOT reproduced by any of the audited endpoints. Two side notes worth
recording so the concern retires cleanly:

- **Per-contact passwords**: `contacts.portal_password_hash` is a
  per-row column. Two contacts under different Companies with
  distinct rows carry distinct hashes; there is no code path that
  writes one hash to more than one contact. If the tester observed a
  "single password" experience, the likely cause is that the browser
  reused the same session across two portal URLs, which is a
  cross-plane / cross-Company session cache issue (MAPPS-630 fixed
  the cross-PLANE case; a cross-Company case would be a similar
  session-carryover fix).
- **Ticket assignment**: an MSP admin who creates a ticket and pins
  its `company_id` to Company A never surfaces that ticket to a
  Company B contact — `list_tickets`, `get_ticket`, and every
  ticket-scoped mutation all refuse cross-Company access at the
  handler layer.

## Multi-Company contacts

Per `contact_portal/models.rs` and the login picker, one email can
back several contacts under different Companies. Each
`ContactSession` (and thus each JWT) is bound to exactly ONE
`contact_id` → one `company_id`. Switching Company requires a fresh
sign-in and a fresh JWT. There is no "current Company selector" in a
single contact session.

## Test coverage

The two integration-test files (listed at the top of this doc) walk
the scoped read + write paths. Together they assert:

- List endpoints refuse to widen visibility when the caller supplies
  a foreign `company_id` (the server force-sets `session.company_id`).
- Detail endpoints 404 (never 403 - would confirm existence to a
  probe) on a row belonging to a foreign Company under the SAME
  tenant AND under a foreign tenant.
- Mutation endpoints (ticket notes, quote accept/decline, ticket
  reopen, branding PATCH, asset report-issue) refuse when the
  target row is foreign.
- Staff bearer callers bypass the scope check as designed.
- A stale JWT that carries a since-revoked cap fails 403 within one
  request (the server DB-loads caps live per prompt 008).

New contact-plane endpoints MUST add their own test case in the
appropriate file (per entity). A new `RequireCallerContext` route
MUST add a test that exercises the `Contact(session)` branch
specifically.

## When to update this doc

- A new `/api/v1/contact/*` route lands: append a row to the table
  and add a regression test if it returns row data.
- A new `RequireCallerContext` handler lands: append a row + test.
- An existing handler's scope check is removed or weakened: STOP the
  PR, restore the check, add a test that would have caught the
  removal.

Do not rewrite this doc from scratch on each audit refresh; append
findings + adjust the affected rows so the git history reads as a
running log.
