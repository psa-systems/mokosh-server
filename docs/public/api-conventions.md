# REST API conventions

This document is the authority for `/api/v1/*` endpoint and resource shapes. Every new route follows it. Exceptions are listed at the bottom with their reason. The route inventory is the set of `.route(...)` calls reachable from `src/api/router.rs`; see [API](api.md) for what each group does.

A rename of an existing route breaks callers (the `mokosh-apps` SPA and any third-party integration), so a route that does not conform is recorded as an exception and tagged "candidate for rename". It is renamed only in its own change, with the callers migrated alongside.

## Route shape

1. **Collections are plural, lowercase and hyphenated.** `/invoices`, `/time-entries`, `/payment-gateways`. Rationale: one spelling per resource, and the URL reads as the thing the list returns. Example: `src/modules/time_tracking/routes.rs` mounts `/time-entries`.
2. **An item is `/{collection}/{id}`.** The id is the server-issued UUID (a natural key such as `{provider}` or `{key}` is allowed where the set is closed and meaningful). Example: `GET /invoices/{invoice_id}`.
3. **Create is `POST` on the collection, read is `GET`, update is `PUT` (or `PATCH` for a partial update), delete is `DELETE` on the item.** `PATCH` is what newer modules use (dashboards, forms, ticket templates, workflow rules, saved reports) and is preferred for new partial-update routes.
4. **A child that cannot exist without its parent is listed and created under the parent; the item is read, changed and deleted flat.** Rationale: the parent id is only needed to scope a list or to attach a new row; once the child has its own id the parent adds nothing, and flat item paths keep every URL to one id. Example: `GET/POST /projects/{id}/tasks` creates and lists, `GET/PUT/DELETE /tasks/{id}` addresses one. Where a child is keyed within its parent rather than by its own id (an ordinal, a link or a composite key), the item path may carry both ids: `PUT/DELETE /teams/{team_id}/members/{user_id}`, `PATCH /kb-executions/{id}/steps/{index}`.
5. **Nest one level at most.** Anything deeper becomes a flat collection filtered by a query parameter (`/ticket-notes?ticket_id=`). Rationale: a three-id path cannot be built without loading two parents. A composite-keyed item under one parent (rule 4) is still one level.
6. **A related collection that can exist on its own stays flat and is filtered.** `GET /invoices?company_id=...`, not `/companies/{id}/invoices`. Nest only for the cases rule 4 covers.
7. **Actions that are not CRUD are a verb after the id.** `POST /invoices/{id}/send`, `POST /invoices/{id}/void`, `POST /quotes/{id}/accept`. Verbs are lowercase and hyphenated, and are always `POST`. A path under `/{collection}/{id}/` is therefore always either a plural sub-collection or a verb.
8. **Collection-level actions and views are a static segment on the collection.** `POST /assets/search`, `GET /invoices/summary`, `POST /invoices/from-time-entries`. Rationale: an id is a UUID, so a static segment cannot collide with one. These words are reserved at that level, which is why a free-form string id (rather than a UUID) is not allowed beside them.
9. **A singleton (one per tenant, per company or per caller) is singular.** `/settings`, `/dispatch`, `/auth/me`, `/tenants/current`. It has no id and no collection.
10. **Module namespaces are allowed when one module owns several collections whose bare names would collide or be ambiguous.** `/kb/articles` and `/kb/categories` (versus `/tickets/categories`), `/sla/policies`, `/rmm/connections`, `/crm/opportunities`, `/integrations/contact-sync/...`. Inside a namespace every rule above applies unchanged. The contacts module is mounted at `/contacts`, so its collections read `/contacts/contacts`, `/contacts/companies` and `/contacts/sites`.
11. **No file extensions and no format segments.** The response is JSON; the only exceptions are file downloads listed below.
12. **No trailing slash.** Collections are mounted without one.
13. **No version below `/api/v1`.** A breaking change adds a route; it does not change an existing one.

## Resource names

1. **A resource is named for its domain noun, plural, in kebab-case, and the name is the table name with `_` turned into `-`.** `time_entries` is `/time-entries`, `payment_gateways` is `/payment-gateways`. Rationale: the table is the one place the noun is already settled, and grep finds both. Where a resource has no table of its own (a computed view such as `/reports/billing`, `/dashboard/summary`), name it for the noun the caller sees.
2. **Do not suffix a resource with its storage shape.** `invoices`, not `invoice-records`.
3. **One level of plural nesting at most** (see Route shape, rule 5). Deeper relationships are query parameters.
4. **A relation row between two resources is named for the relation.** `/asset-relationships`, `/tasks/{id}/depends-on/{other}`.
5. **Do not repeat the resource name inside a verb.** `/invoices/{id}/send`, not `/invoices/{id}/send-invoice`.

## HTTP methods and idempotency

| Method | Meaning | Safe | Idempotent |
| --- | --- | --- | --- |
| `GET` (and `HEAD`) | Read. Never changes state; no side effects beyond logging and rate limiting. | yes | yes |
| `PUT` | Update an item (or replace a singleton such as `/settings/email`). The same request sent twice leaves the same state. | no | yes |
| `PATCH` | Partial update of an item. Idempotent: send the fields to set, not a delta. | no | yes |
| `DELETE` | Remove the item. A second delete of the same id is a no-op or a 404, never a second effect. | no | yes |
| `POST` | Create, or perform an action. Repeating it may repeat the effect. | no | no |

A `POST` that is safe to retry says so in its handler (the inbound email intake deduplicates on `Message-Id`). A client must not retry a `POST` blindly.

## Query parameters

- **Names are `snake_case`**, the same as JSON request and response fields: `company_id`, `per_page`, `sort_dir`.
- **Pagination is `page` (1-indexed) and `per_page`**, defined once in `src/utils/pagination.rs` as `PaginationParams`. `per_page` is capped at 100; a larger value is rejected with 400, never silently clamped. Sorting is `sort` (a field from the route's allow-list) and `sort_dir` (`asc` or `desc`). A paginated response is `{"data": [...], "meta": {"page", "per_page", "total", "total_pages", "has_next", "has_prev"}}`. New list routes use `PaginationParams` (flattened into their query struct) rather than inventing `limit` and `offset`.
- **Filters are one parameter per field**, named for the field: `company_id`, `status`. A date range is `from` and `to`. Free-text search is `q`. A route rejects a filter value it cannot parse with 400 (`BAD_REQUEST`) and a field-level `errors` array, never an empty result.
- **Filters are for narrowing a list, never for choosing what a route does.** A different behavior is a different route or a verb.

## Error shapes

Every 4xx and 5xx response carries one envelope, built from `AppError` in `src/utils/error.rs`:

```json
{"error": {"code": "VALIDATION_ERROR", "message": "Validation failed: ...", "errors": [{"field": "name", "message": "...", "code": "..."}]}}
```

- `code` is a stable machine string (`UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `VALIDATION_ERROR`, `BAD_REQUEST`, `CONFLICT`, `GONE`, `TOKEN_EXPIRED`, `ACCOUNT_DELETED`, `RATE_LIMITED`, `PAYLOAD_TOO_LARGE`, `INTERNAL_ERROR`, and the rest of `AppError::error_code`). A client branches on `code`, not on `message`.
- `errors` is present only for field-level validation and rejected query parameters.
- A request rejected before a handler runs (malformed JSON, wrong content type, oversized body) is rewritten into the same envelope by `normalize_error_envelope`; no plain-text body leaves the API.
- **One documented exception:** a rate-limited response (429) is a flat body, `{"error": "rate_limited", "message": "...", "retry_after_seconds": N}`, with a `Retry-After` header and `Cache-Control: no-store`. Branch on the 429 status, not on `error.code`.

## Sub-prefixes

| Prefix | Auth | Meaning |
| --- | --- | --- |
| `/public/` | none | Unauthenticated by design, per-IP rate limited as one nest. Holds the feature probe, signed-out branding, public KB and inline-image reads, request forms and OAuth redirect URIs. Nothing under it may change state for a caller it cannot identify, except a form submission that is itself rate limited. |
| `/contact/` | contact Bearer | The contact (customer) plane. Singular, to tell it apart from the staff `/contacts/` namespace; do not add a staff route under `/contact/`, or a contact route under `/contacts/`. |
| `/auth/me/` | session | Resources owned by the calling user: `/auth/me/sessions`, `/auth/me/api-keys`, `/auth/me/mfa/...`. New caller-owned resources go here. The contact plane mirrors it at `/contact/auth/me/`. |
| `/me/` | session | Caller-scoped views of a module's data that is not an account credential: `/me/teams`, `/me/notification-preferences`. |
| `/platform/` | platform-admin JWT | The deployment-operator surface, with its own credential store. |
| `/admin/` | operator | Operator-only diagnostics (`/admin/providers/status`). |
| `/bunyip/`, `/stripe/`, `/paypal/`, `/webhooks/` | signature | Signed receivers (see exceptions). One tree per sender. |
| `/integrations/{name}/` | session | Connect, authorize, disconnect and configure a third-party integration. |

## Classification of existing routes

Each mounted route is classified as one of:

- **Conforming:** the path, verb and resource name match this document.
- **Exception:** it does not, for the reason in the Note column. "Candidate for rename" marks an exception with no reason other than age; each needs its own change with the callers migrated. Anything else is an exception that stays (a provider-defined path, an operator page, an HMAC ingest whose URL is configured in deployed agents).
- **Deprecated:** scheduled for removal. None of the current routes is deprecated.

The inventory was built from the `.route(...)` calls under `src/modules/` and `src/providers/` and the mount points in `src/api/router.rs`. A route registered only in a test fixture is not listed. The multi-tenant routes (`/tenants`, `/teams`, `/me/teams`) exist only in builds with the `multi-tenant` feature. A `Methods` cell with several verbs is one registered path (`GET/POST` is two routes).

Totals: 470 paths, 656 method-and-path routes. 426 paths (605 routes) conform; 44 paths (51 routes) are exceptions, of which 30 paths carry a "candidate for rename" or reserved-name tag and the rest are provider-, signature- or operator-defined.

### Exception groups at a glance

- **Provider- or sender-defined paths (stay as they are):** signed receivers (`/bunyip/...`, `/stripe/...`, `/paypal/...`, `/webhooks/...`), OAuth redirect URIs (`/public/**/callback`), HMAC ingest (`/rmm/alerts`, `/rmm/status`), the inbound email gateway (`/email-intake`), the operator HTML page (`/admin/providers/status.html`).
- **Free-form string segment beside static siblings:** `/settings/{category}`, `/{company_id}/{asset}` and `/{tenant_id}/{asset}` branding paths (candidates for rename to `.../branding/{asset}`).
- **Deeper than one level, or an item addressed through a parent although its id is unique:** ticket-note attachments, `PUT /tickets/{id}/notes/{note_id}`, `/quotes/{id}/lines/{line_id}`, `DELETE /kb/articles/{id}/attachments/{attachment_id}`, `/audit-log/entity/{type}/{id}`.
- **Naming:** `/kb/articles/{id}/not_helpful`, `/workday`, `/time-off/{id}/approval`, `/audit-log/export.csv`.
- **Mounted in the wrong namespace:** the staff user routes under `/auth/users`, `/companies/{id}/documentation`, `/contacts/{id}/notes`.

### Session tree

Mounted at `/api/v1`. Staff Bearer unless a note says otherwise. A few routes are dual-plane (a contact Bearer also reaches them). Paths below are relative to `/api/v1`.

| Methods | Path | Class | Note |
| --- | --- | --- | --- |
| GET | `/health` | Conforming |  |
| GET | `/ready` | Conforming |  |
| GET | `/version` | Conforming |  |
| GET | `/version/check` | Conforming |  |
| GET | `/providers` | Conforming |  |
| GET | `/admin/providers/status` | Conforming |  |
| GET | `/admin/providers/status.html` | Exception | Operator HTML page, not JSON; extension kept so a browser can open it |
| POST | `/admin/providers/status/refresh` | Conforming |  |
| POST | `/grants/invitations` | Conforming |  |
| GET | `/grants/invitations` | Conforming |  |
| DELETE | `/grants/invitations/{id}` | Conforming |  |
| GET | `/my-grants/invitations` | Conforming |  |
| POST | `/my-grants/invitations/{id}/accept` | Conforming |  |
| POST | `/my-grants/invitations/{id}/decline` | Conforming |  |
| GET | `/grants/invitations/by-token/{token}` | Conforming |  |
| POST | `/grants/invitations/by-token/{token}/accept` | Conforming |  |
| POST | `/grants/invitations/by-token/{token}/decline` | Conforming |  |
| DELETE | `/my-grants/{id}` | Conforming |  |
| POST | `/auth/login` | Conforming |  |
| POST | `/auth/select-tenant` | Conforming |  |
| POST | `/auth/switch-tenant/{tenant_id}` | Conforming |  |
| POST | `/auth/logout` | Conforming |  |
| POST | `/auth/logout-all` | Conforming |  |
| POST | `/auth/refresh` | Conforming |  |
| POST | `/auth/forgot-password` | Conforming |  |
| POST | `/auth/reset-password` | Conforming |  |
| GET | `/auth/set-password/context/{token}` | Conforming |  |
| GET | `/auth/me` | Conforming |  |
| PUT | `/auth/me` | Conforming |  |
| GET | `/auth/memberships` | Exception | Tenant user management mounted under the `/auth` module namespace; candidate for rename to `/users` |
| POST | `/auth/me/complete-onboarding` | Conforming |  |
| PUT | `/auth/me/password` | Conforming |  |
| GET | `/auth/me/sessions` | Conforming |  |
| DELETE | `/auth/me/sessions/{session_id}` | Conforming |  |
| POST | `/auth/me/mfa/setup` | Conforming |  |
| POST | `/auth/me/mfa/enable` | Conforming |  |
| POST | `/auth/me/mfa/disable` | Conforming |  |
| GET | `/auth/me/api-keys` | Conforming |  |
| POST | `/auth/me/api-keys` | Conforming |  |
| DELETE | `/auth/me/api-keys/{key_id}` | Conforming |  |
| GET | `/auth/directory` | Exception | Tenant user management mounted under the `/auth` module namespace; candidate for rename to `/users` |
| GET | `/auth/users` | Exception | Tenant user management mounted under the `/auth` module namespace; candidate for rename to `/users` |
| POST | `/auth/users` | Exception | Tenant user management mounted under the `/auth` module namespace; candidate for rename to `/users` |
| GET | `/auth/users/{user_id}` | Exception | Tenant user management mounted under the `/auth` module namespace; candidate for rename to `/users` |
| PUT | `/auth/users/{user_id}` | Exception | Tenant user management mounted under the `/auth` module namespace; candidate for rename to `/users` |
| POST | `/platform/login` | Conforming |  |
| PUT | `/platform/me/password` | Conforming |  |
| POST | `/platform/me/mfa/setup` | Conforming |  |
| POST | `/platform/me/mfa/enable` | Conforming |  |
| POST | `/platform/me/mfa/disable` | Conforming |  |
| GET | `/tenants` | Conforming |  |
| POST | `/tenants` | Conforming |  |
| POST | `/tenants/self-serve` | Conforming |  |
| POST | `/tenants/additional` | Conforming |  |
| GET | `/tenants/current` | Conforming |  |
| PUT | `/tenants/current` | Conforming |  |
| PUT | `/tenants/current/organization` | Conforming |  |
| PUT | `/tenants/current/logo` | Conforming |  |
| DELETE | `/tenants/current/logo` | Conforming |  |
| GET | `/tenants/{tenant_id}` | Conforming |  |
| PUT | `/tenants/{tenant_id}` | Conforming |  |
| POST | `/tenants/{tenant_id}/suspend` | Conforming |  |
| POST | `/tenants/{tenant_id}/activate` | Conforming |  |
| GET | `/tenants/{tenant_id}/usage` | Conforming |  |
| GET | `/tenants/{tenant_id}/modules/{module}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| PUT | `/tenants/{tenant_id}/modules/{module}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET/POST | `/teams` | Conforming |  |
| GET/PUT/DELETE | `/teams/{team_id}` | Conforming |  |
| GET/POST | `/teams/{team_id}/members` | Conforming |  |
| PUT/DELETE | `/teams/{team_id}/members/{user_id}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/me/teams` | Conforming |  |
| GET | `/contacts/companies` | Conforming |  |
| POST | `/contacts/companies` | Conforming |  |
| GET | `/contacts/companies/website-probe` | Conforming |  |
| GET | `/contacts/companies/{company_id}` | Conforming |  |
| PUT | `/contacts/companies/{company_id}` | Conforming |  |
| DELETE | `/contacts/companies/{company_id}` | Conforming |  |
| GET | `/contacts/companies/{company_id}/deletion-preview` | Conforming |  |
| GET | `/contacts/companies/{company_id}/contacts` | Conforming |  |
| GET | `/contacts/companies/{company_id}/sites` | Conforming |  |
| GET/POST | `/contacts/companies/{company_id}/portal-roles` | Conforming |  |
| GET/PUT/DELETE | `/contacts/companies/{company_id}/portal-roles/{role_id}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/contacts/contacts` | Conforming |  |
| POST | `/contacts/contacts` | Conforming |  |
| GET | `/contacts/contacts/field-values` | Conforming |  |
| GET | `/contacts/contacts/{contact_id}` | Conforming |  |
| PUT | `/contacts/contacts/{contact_id}` | Conforming |  |
| DELETE | `/contacts/contacts/{contact_id}` | Conforming |  |
| GET | `/contacts/contacts/portal-roles` | Conforming |  |
| POST | `/contacts/contacts/{contact_id}/grant-portal-access` | Conforming |  |
| POST | `/contacts/contacts/{contact_id}/resend-portal-invite` | Conforming |  |
| POST | `/contacts/contacts/{contact_id}/revoke-portal-access` | Conforming |  |
| GET/PUT | `/contacts/contacts/{contact_id}/portal-roles` | Conforming |  |
| GET | `/contacts/contacts/{contact_id}/access-requests` | Conforming |  |
| POST | `/contacts/contacts/access-requests/{request_id}/resolve` | Conforming |  |
| GET/POST | `/contacts/company-industries` | Conforming |  |
| PUT/DELETE | `/contacts/company-industries/{id}` | Conforming |  |
| POST | `/contacts/sites` | Conforming |  |
| GET | `/contacts/sites/{site_id}` | Conforming |  |
| PUT | `/contacts/sites/{site_id}` | Conforming |  |
| DELETE | `/contacts/sites/{site_id}` | Conforming |  |
| GET | `/portal-roles` | Conforming |  |
| POST | `/portal-roles` | Conforming |  |
| GET | `/portal-roles/capabilities` | Conforming |  |
| GET | `/portal-roles/{id}` | Conforming |  |
| PUT | `/portal-roles/{id}` | Conforming |  |
| DELETE | `/portal-roles/{id}` | Conforming |  |
| GET | `/contacts/{contact_id}/notes` | Exception | A contact lives at `/contacts/contacts/{id}`; candidate for rename to `/contacts/contacts/{id}/notes` |
| GET | `/tickets` | Conforming |  |
| POST | `/tickets` | Conforming |  |
| GET | `/tickets/{ticket_id}` | Conforming |  |
| GET | `/tickets/{ticket_id}/sla` | Conforming |  |
| PUT | `/tickets/{ticket_id}` | Conforming |  |
| PATCH | `/tickets/{ticket_id}` | Conforming |  |
| DELETE | `/tickets/{ticket_id}` | Conforming |  |
| POST | `/tickets/{ticket_id}/assign` | Conforming |  |
| POST | `/tickets/{ticket_id}/approvals/request` | Conforming |  |
| POST | `/tickets/{ticket_id}/reopen` | Conforming |  |
| POST | `/tickets/{ticket_id}/attachments` | Conforming |  |
| GET | `/tickets/{ticket_id}/notes` | Conforming |  |
| POST | `/tickets/{ticket_id}/notes` | Conforming |  |
| PUT | `/tickets/{ticket_id}/notes/{note_id}` | Exception | Item addressed through its parent although its id is globally unique; candidate for rename |
| GET/POST | `/tickets/statuses` | Conforming |  |
| PUT/DELETE | `/tickets/statuses/{id}` | Conforming |  |
| GET/POST | `/tickets/priorities` | Conforming |  |
| PUT/DELETE | `/tickets/priorities/{id}` | Conforming |  |
| GET/POST | `/tickets/queues` | Conforming |  |
| PUT/DELETE | `/tickets/queues/{id}` | Conforming |  |
| GET/POST | `/tickets/types` | Conforming |  |
| PUT/DELETE | `/tickets/types/{id}` | Conforming |  |
| GET/POST | `/tickets/categories` | Conforming |  |
| PUT/DELETE | `/tickets/categories/{id}` | Conforming |  |
| GET/POST | `/tickets/saved-views` | Conforming |  |
| PUT/DELETE | `/tickets/saved-views/{id}` | Conforming |  |
| POST | `/tickets/{ticket_id}/attachments/inline` | Conforming |  |
| GET/POST | `/tickets/{ticket_id}/notes/{note_id}/attachments` | Exception | Two levels of plural nesting; candidate for a flat resource filtered by `note_id` |
| GET/DELETE | `/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}` | Exception | Two levels of plural nesting; candidate for a flat resource filtered by `note_id` |
| GET/POST | `/work-types` | Conforming |  |
| PUT/DELETE | `/work-types/{id}` | Conforming |  |
| GET/POST | `/time-entries` | Conforming |  |
| GET | `/time-entries/summary` | Conforming |  |
| GET/PUT/DELETE | `/time-entries/{id}` | Conforming |  |
| GET | `/timesheets` | Conforming |  |
| POST | `/timesheets/{user_id}/{week_start}/submit` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| POST | `/timesheets/{user_id}/{week_start}/withdraw` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| POST | `/timesheets/{user_id}/{week_start}/approve` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| POST | `/timesheets/{user_id}/{week_start}/reject` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/timers/active` | Conforming |  |
| POST | `/timers/start` | Conforming |  |
| POST | `/timers/{id}/stop` | Conforming |  |
| GET | `/workday` | Exception | Per-user singleton with a closed-compound singular name; candidate for rename to `/work-day` |
| POST | `/workday/clock-in` | Exception | Per-user singleton with a closed-compound singular name; candidate for rename to `/work-day` |
| POST | `/workday/clock-out` | Exception | Per-user singleton with a closed-compound singular name; candidate for rename to `/work-day` |
| POST | `/workday/break/start` | Exception | Per-user singleton with a closed-compound singular name; candidate for rename to `/work-day` |
| POST | `/workday/break/end` | Exception | Per-user singleton with a closed-compound singular name; candidate for rename to `/work-day` |
| PUT/DELETE | `/workday/segments/{id}` | Exception | Per-user singleton with a closed-compound singular name; candidate for rename to `/work-day` |
| GET/POST | `/time-rounding-rules` | Conforming |  |
| PUT/DELETE | `/time-rounding-rules/{id}` | Conforming |  |
| GET/POST | `/mileage-entries` | Conforming |  |
| GET/PUT/DELETE | `/mileage-entries/{id}` | Conforming |  |
| GET/POST | `/projects` | Conforming |  |
| GET | `/projects/summary` | Conforming |  |
| GET/PUT/DELETE | `/projects/{id}` | Conforming |  |
| GET/POST | `/projects/{id}/phases` | Conforming |  |
| PUT/DELETE | `/phases/{phase_id}` | Conforming |  |
| GET/POST | `/task-statuses` | Conforming |  |
| PUT/DELETE | `/task-statuses/{id}` | Conforming |  |
| GET/POST | `/project-types` | Conforming |  |
| PUT/DELETE | `/project-types/{id}` | Conforming |  |
| GET/POST | `/projects/{id}/tasks` | Conforming |  |
| GET/PUT/DELETE | `/tasks/{id}` | Conforming |  |
| POST/DELETE | `/tasks/{id}/depends-on/{other}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET/POST | `/contracts` | Conforming |  |
| GET/PUT/DELETE | `/contracts/{id}` | Conforming |  |
| GET/POST | `/contracts/{id}/items` | Conforming |  |
| PUT/DELETE | `/contract-items/{id}` | Conforming |  |
| GET | `/contracts/{id}/hour-balance` | Conforming |  |
| GET/POST | `/rate-cards` | Conforming |  |
| GET/PUT/DELETE | `/rate-cards/{id}` | Conforming |  |
| GET/POST | `/rate-cards/{id}/items` | Conforming |  |
| DELETE | `/rate-card-items/{id}` | Conforming |  |
| GET/POST | `/sla/policies` | Conforming |  |
| GET/PUT/DELETE | `/sla/policies/{id}` | Conforming |  |
| GET/POST | `/sla/policies/{id}/targets` | Conforming |  |
| DELETE | `/sla/targets/{id}` | Conforming |  |
| GET/POST | `/sla/business-hours` | Conforming |  |
| PUT/DELETE | `/sla/business-hours/{id}` | Conforming |  |
| GET/POST | `/sla/holiday-calendars` | Conforming |  |
| PUT/DELETE | `/sla/holiday-calendars/{id}` | Conforming |  |
| POST | `/sla/tickets/{id}/evaluate` | Conforming |  |
| GET/POST | `/vendors` | Conforming |  |
| GET/PUT/DELETE | `/vendors/{id}` | Conforming |  |
| GET/POST | `/expense-categories` | Conforming |  |
| PUT | `/expense-categories/{id}` | Conforming |  |
| GET/POST | `/bills` | Conforming |  |
| GET | `/bills/{id}` | Conforming |  |
| POST | `/bills/{id}/approve` | Conforming |  |
| POST | `/bills/{id}/void` | Conforming |  |
| GET/POST | `/bills/{id}/payments` | Conforming |  |
| GET/POST | `/expenses` | Conforming |  |
| GET | `/expenses/{id}` | Conforming |  |
| POST | `/expenses/{id}/submit` | Conforming |  |
| POST | `/expenses/{id}/approve` | Conforming |  |
| POST | `/expenses/{id}/reject` | Conforming |  |
| POST | `/expenses/{id}/reimburse` | Conforming |  |
| GET/POST | `/asset-types` | Conforming |  |
| PUT/DELETE | `/asset-types/{id}` | Conforming |  |
| GET/POST | `/assets` | Conforming |  |
| POST | `/assets/search` | Conforming |  |
| POST | `/assets/search/facets` | Conforming |  |
| POST | `/assets/bulk-create` | Conforming |  |
| POST | `/assets/exists` | Conforming |  |
| GET/PUT/PATCH/DELETE | `/assets/{id}` | Conforming |  |
| GET/POST | `/assets/{id}/relationships` | Conforming |  |
| DELETE | `/asset-relationships/{id}` | Conforming |  |
| GET | `/assets/{id}/impact` | Conforming |  |
| POST | `/assets/{id}/report-issue` | Conforming |  |
| GET/POST | `/assets/{id}/configuration-items` | Conforming |  |
| GET/DELETE | `/configuration-items/{id}` | Conforming |  |
| GET/POST | `/assets/{id}/credentials` | Conforming |  |
| GET/DELETE | `/credentials/{id}` | Conforming |  |
| GET | `/assets/{id}/audit-log` | Conforming |  |
| GET/POST | `/asset-models` | Conforming |  |
| GET | `/asset-models/signature-detector` | Conforming |  |
| GET/PUT/DELETE | `/asset-models/{id}` | Conforming |  |
| GET/POST | `/asset-templates` | Conforming |  |
| GET/PUT/DELETE | `/asset-templates/{id}` | Conforming |  |
| GET/POST | `/notification-channels` | Conforming |  |
| PUT/DELETE | `/notification-channels/{id}` | Conforming |  |
| GET/POST | `/notification-templates` | Conforming |  |
| PUT/DELETE | `/notification-templates/{id}` | Conforming |  |
| GET/PUT | `/me/notification-preferences` | Conforming |  |
| GET | `/notifications` | Conforming |  |
| POST | `/notifications/{id}/read` | Conforming |  |
| GET/POST | `/notification-rules` | Conforming |  |
| PUT/DELETE | `/notification-rules/{id}` | Conforming |  |
| POST | `/notifications/dispatch` | Conforming |  |
| POST | `/notifications/preview` | Conforming |  |
| GET/POST | `/rmm/connections` | Conforming |  |
| GET/PUT/DELETE | `/rmm/connections/{id}` | Conforming |  |
| POST | `/rmm/connections/{id}/test` | Conforming |  |
| GET/POST | `/rmm/device-mappings` | Conforming |  |
| PUT/DELETE | `/rmm/device-mappings/{id}` | Conforming |  |
| GET/POST | `/rmm/alert-rules` | Conforming |  |
| PUT/DELETE | `/rmm/alert-rules/{id}` | Conforming |  |
| POST | `/rmm/alerts` | Exception | Ingest authenticated by an HMAC signature, not a session; path fixed in deployed agents |
| POST | `/rmm/status` | Exception | Ingest authenticated by an HMAC signature, not a session; path fixed in deployed agents |
| GET | `/status/systems/{id}/current` | Conforming |  |
| GET | `/status/companies/{company_id}/backup` | Conforming |  |
| GET | `/reports/status/backup-success-rate` | Conforming |  |
| GET | `/reports/status/uptime` | Conforming |  |
| GET/POST | `/crm/opportunities` | Conforming |  |
| GET/PUT/DELETE | `/crm/opportunities/{id}` | Conforming |  |
| POST | `/crm/opportunities/{id}/close` | Conforming |  |
| GET | `/reports` | Conforming |  |
| GET | `/reports/dashboard` | Conforming |  |
| GET | `/reports/tickets` | Conforming |  |
| GET | `/reports/time` | Conforming |  |
| GET | `/reports/request-types` | Conforming |  |
| GET | `/reports/billing` | Conforming |  |
| GET | `/reports/projects` | Conforming |  |
| GET | `/reports/clients` | Conforming |  |
| GET | `/reports/custom/schema` | Conforming |  |
| POST | `/reports/custom` | Conforming |  |
| GET | `/reports/{report}/export` | Conforming |  |
| GET/POST | `/reports/saved` | Conforming |  |
| GET/PATCH/DELETE | `/reports/saved/{id}` | Conforming |  |
| POST | `/reports/saved/{id}/execute` | Conforming |  |
| GET/POST | `/reports/saved/{id}/schedules` | Conforming |  |
| GET/PATCH/DELETE | `/reports/schedules/{schedule_id}` | Conforming |  |
| GET/POST | `/workflow-rules` | Conforming |  |
| GET/PATCH/DELETE | `/workflow-rules/{id}` | Conforming |  |
| GET | `/tickets/{id}/workflow-runs` | Conforming |  |
| GET/POST | `/ticket-templates` | Conforming |  |
| GET/PATCH/DELETE | `/ticket-templates/{id}` | Conforming |  |
| GET/POST | `/forms` | Conforming |  |
| GET/PUT | `/forms/drafts` | Conforming |  |
| DELETE | `/forms/drafts/{id}` | Conforming |  |
| GET/PATCH | `/forms/{id}` | Conforming |  |
| GET | `/forms/{id}/submissions` | Conforming |  |
| GET/POST | `/form-request-links` | Conforming |  |
| GET | `/search` | Conforming |  |
| GET/POST | `/dashboards` | Conforming |  |
| GET | `/dashboards/default` | Conforming |  |
| GET/PATCH/DELETE | `/dashboards/{id}` | Conforming |  |
| GET/POST | `/dashboards/{id}/schedules` | Conforming |  |
| GET/PATCH/DELETE | `/dashboards/schedules/{schedule_id}` | Conforming |  |
| POST | `/email-intake` | Exception | Ingest authenticated by a tenant intake bearer, not a session; path fixed in deployed gateways |
| GET/POST | `/intake-tokens` | Conforming |  |
| DELETE | `/intake-tokens/{id}` | Conforming |  |
| GET | `/email-intake-log/{id}` | Conforming |  |
| GET/POST | `/tickets/{ticket_id}/approvals` | Conforming |  |
| GET/POST | `/time-entries/{entity_id}/approvals` | Conforming |  |
| GET/POST | `/change-requests/{entity_id}/approvals` | Conforming |  |
| GET/POST | `/quotes/{entity_id}/approvals` | Conforming |  |
| GET | `/approvals/pending` | Conforming |  |
| GET | `/approvals/pending/count` | Conforming |  |
| POST | `/approvals/{id}/decision` | Conforming |  |
| DELETE | `/approvals/{id}` | Conforming |  |
| GET/PUT | `/settings` | Conforming |  |
| GET | `/settings/modules` | Conforming |  |
| GET/PUT | `/settings/modules/{module}` | Conforming |  |
| GET/PUT | `/settings/email` | Conforming |  |
| POST | `/settings/email/test-send` | Conforming |  |
| POST | `/settings/email/verify` | Conforming |  |
| GET/PUT | `/settings/google-contacts-client` | Conforming |  |
| GET/PUT | `/settings/microsoft-contacts-client` | Conforming |  |
| GET/PUT | `/settings/app-name` | Conforming |  |
| GET | `/settings/{category}` | Exception | Free-form `{category}` shares a level with static siblings (`modules`, `email`, `app-name`, ...); those names are reserved |
| GET/PUT/DELETE | `/settings/{category}/{key}` | Exception | Free-form `{category}` shares a level with static siblings (`modules`, `email`, `app-name`, ...); those names are reserved |
| GET | `/audit-log` | Conforming |  |
| GET | `/audit-log/export.csv` | Exception | File extension in the path; candidate for rename |
| GET | `/audit-log/entity/{entity_type}/{entity_id}` | Exception | Polymorphic entity reference in the path; candidate for `/audit-log?entity_type=&entity_id=` |
| GET | `/ip-enrichment` | Conforming |  |
| GET/POST | `/invitations` | Conforming |  |
| DELETE | `/invitations/{id}` | Conforming |  |
| GET | `/members` | Conforming |  |
| GET | `/integrations` | Conforming |  |
| GET/POST | `/invoices` | Conforming |  |
| GET | `/invoices/summary` | Conforming |  |
| POST | `/invoices/from-time-entries` | Conforming |  |
| GET/PUT | `/invoices/{invoice_id}` | Conforming |  |
| POST | `/invoices/{invoice_id}/write-off` | Conforming |  |
| POST | `/invoices/{invoice_id}/void` | Conforming |  |
| POST | `/invoices/{invoice_id}/amend` | Conforming |  |
| GET | `/invoices/{invoice_id}/pdf` | Conforming |  |
| GET | `/invoices/{invoice_id}/delivery-options` | Conforming |  |
| POST | `/invoices/{invoice_id}/pay` | Conforming |  |
| GET | `/invoices/{invoice_id}/payments` | Conforming |  |
| GET | `/invoices/{invoice_id}/payment-readiness` | Conforming |  |
| GET/POST | `/products` | Conforming |  |
| GET/PUT/DELETE | `/products/{product_id}` | Conforming |  |
| GET | `/statements` | Conforming |  |
| GET | `/statements/pdf` | Conforming |  |
| GET/POST | `/credit-notes` | Conforming |  |
| GET | `/credit-notes/{credit_note_id}` | Conforming |  |
| GET | `/credit-notes/{credit_note_id}/pdf` | Conforming |  |
| POST | `/credit-notes/{credit_note_id}/void` | Conforming |  |
| GET/POST | `/payments` | Conforming |  |
| DELETE | `/payments/{payment_id}` | Conforming |  |
| GET/PUT | `/payment-gateways` | Conforming |  |
| GET | `/payment-gateways/webhook-endpoints` | Conforming |  |
| GET | `/payment-gateways/webhook-deliveries` | Conforming |  |
| DELETE | `/payment-gateways/{provider}` | Conforming |  |
| POST | `/payment-gateways/{provider}/check` | Conforming |  |
| GET/POST | `/tax-rates` | Conforming |  |
| PUT/DELETE | `/tax-rates/{id}` | Conforming |  |
| GET | `/tax-rates/lookup` | Conforming |  |
| GET/POST | `/payment-terms` | Conforming |  |
| PUT/DELETE | `/payment-terms/{id}` | Conforming |  |
| GET | `/data/export` | Conforming |  |
| POST | `/data/import` | Conforming |  |
| POST | `/data/seed-demo` | Conforming |  |
| GET | `/invoice-issuer-mappings/companies` | Conforming |  |
| PUT | `/invoice-issuer-mappings/companies/{provider}/{company_id}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/invoice-issuer-mappings/products` | Conforming |  |
| PUT | `/invoice-issuer-mappings/products/{provider}/{product_id}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/invoice-issuer-mappings/vendors` | Conforming |  |
| PUT | `/invoice-issuer-mappings/vendors/{provider}/{vendor_id}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/invoice-issuer-mappings/expense-accounts` | Conforming |  |
| PUT | `/invoice-issuer-mappings/expense-accounts/{provider}/{category_id}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/invoice-issuer-mappings/people` | Conforming |  |
| PUT | `/invoice-issuer-mappings/people/{provider}/{user_id}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET/POST | `/appointments` | Conforming |  |
| GET | `/calendar/appointments` | Conforming |  |
| GET/PUT/DELETE | `/appointments/{id}` | Conforming |  |
| GET/PUT | `/users/{user_id}/availability` | Conforming |  |
| GET/POST | `/time-off` | Conforming |  |
| GET/DELETE | `/time-off/{id}` | Conforming |  |
| POST | `/time-off/{id}/approval` | Exception | Singular sub-resource where sibling routes use `/approvals`; candidate for rename |
| GET/POST | `/on-call-schedules` | Conforming |  |
| PUT/DELETE | `/on-call-schedules/{id}` | Conforming |  |
| GET | `/on-call/now` | Conforming |  |
| GET/POST | `/scheduling-templates` | Conforming |  |
| GET/PUT/DELETE | `/scheduling-templates/{id}` | Conforming |  |
| GET | `/dispatch` | Conforming |  |
| GET | `/companies/{company_id}/documentation` | Exception | Company routes live under `/contacts/companies`; candidate for rename to `/contacts/companies/{id}/documentation` |
| GET/POST | `/kb/articles/{id}/attachments` | Conforming |  |
| DELETE | `/kb/articles/{id}/attachments/{attachment_id}` | Exception | Delete addressed through the parent while reads use flat `/kb/attachments/{id}`; candidate for rename |
| GET/POST | `/kb/categories` | Conforming |  |
| PUT/DELETE | `/kb/categories/{id}` | Conforming |  |
| GET/POST | `/kb/articles` | Conforming |  |
| GET/PUT/DELETE | `/kb/articles/{id}` | Conforming |  |
| GET/PUT/DELETE | `/kb/articles/{id}/draft` | Conforming |  |
| GET | `/kb/articles/{id}/versions` | Conforming |  |
| POST | `/kb/articles/{id}/versions/{version_number}/restore` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| POST | `/kb/articles/{id}/render` | Conforming |  |
| POST | `/kb/articles/{id}/helpful` | Conforming |  |
| POST | `/kb/articles/{id}/not_helpful` | Exception | Underscore verb; candidate for rename to `not-helpful` |
| GET | `/kb/articles/{id}/vote` | Conforming |  |
| GET | `/kb/top-ticket-driving-articles` | Conforming |  |
| GET | `/kb/articles/{id}/measured-duration` | Conforming |  |
| GET | `/kb/articles/{id}/tickets` | Conforming |  |
| GET/POST | `/kb/articles/{id}/comments` | Conforming |  |
| PUT/DELETE | `/kb/comments/{id}` | Conforming |  |
| POST | `/kb/comments/{id}/resolve` | Conforming |  |
| POST | `/kb/comments/{id}/unresolve` | Conforming |  |
| GET/POST | `/tickets/{ticket_id}/kb-executions` | Conforming |  |
| GET | `/kb-executions/{id}` | Conforming |  |
| PATCH | `/kb-executions/{id}/steps/{index}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| GET | `/settings/feature-toggles` | Conforming |  |
| PUT | `/settings/feature-toggles/{key}` | Conforming |  |
| PUT/DELETE | `/companies/{company_id}/{asset}` | Exception | Bare string `{asset}` under an id can be mistaken for a sub-resource or verb; candidate for rename to `.../branding/{asset}` |
| PUT/DELETE | `/tenants/current/branding/{asset}` | Conforming | Singleton `branding` of the caller tenant; `{asset}` is a closed set |
| GET | `/integrations/contact-sync` | Conforming |  |
| POST | `/integrations/contact-sync/google/authorize` | Conforming |  |
| POST | `/integrations/contact-sync/google/disconnect` | Conforming |  |
| POST | `/integrations/contact-sync/icloud/connect` | Conforming |  |
| POST | `/integrations/contact-sync/icloud/disconnect` | Conforming |  |
| POST | `/integrations/contact-sync/microsoft/authorize` | Conforming |  |
| POST | `/integrations/contact-sync/microsoft/disconnect` | Conforming |  |
| PUT | `/integrations/contact-sync/selection` | Conforming |  |
| PUT | `/integrations/contact-sync/schedule` | Conforming |  |
| POST | `/integrations/contact-sync/preview` | Conforming |  |
| GET/POST | `/integrations/contact-sync/runs` | Conforming |  |
| GET | `/integrations/contact-sync/runs/{run_id}` | Conforming |  |
| POST | `/integrations/contact-sync/runs/{run_id}/cancel` | Conforming |  |
| GET | `/integrations/contact-sync/review-queue` | Conforming |  |
| POST | `/integrations/contact-sync/review-queue/resolve` | Conforming |  |
| GET/POST | `/integrations/contact-sync/vcard/uploads` | Conforming |  |
| POST | `/integrations/contact-sync/vcard/uploads/{file_id}/preview` | Conforming |  |
| POST | `/integrations/contact-sync/vcard/uploads/{file_id}/import` | Conforming |  |
| GET | `/contacts/contacts/{contact_id}/sync` | Conforming |  |
| DELETE | `/contacts/contacts/{contact_id}/sync/locks/{field}` | Conforming | Keyed within its parent (ordinal, link or composite key) |
| POST | `/contacts/contacts/{contact_id}/sync/unlink` | Conforming |  |
| POST | `/contacts/contacts/{contact_id}/sync/remove-imported-data` | Conforming |  |
| GET | `/integrations/invoice-issuer/{provider}` | Conforming |  |
| POST | `/integrations/invoice-issuer/{provider}/authorize` | Conforming |  |
| POST | `/integrations/invoice-issuer/{provider}/disconnect` | Conforming |  |
| PUT | `/integrations/invoice-issuer/{provider}/bills` | Conforming |  |
| PUT | `/integrations/invoice-issuer/{provider}/payment-account` | Conforming |  |

### Public tree

Mounted at `/api/v1/public`. Unauthenticated by design; per-IP rate limited as one nest. Paths below are relative to `/api/v1`.

| Methods | Path | Class | Note |
| --- | --- | --- | --- |
| GET | `/public/tenants/{tenant_id}/logo` | Conforming |  |
| GET | `/public/tickets/attachments/{attachment_id}` | Conforming |  |
| GET | `/public/kb/attachments/{attachment_id}` | Conforming |  |
| GET | `/public/config` | Conforming |  |
| GET/POST | `/public/request-forms/{token}` | Conforming |  |
| GET | `/public/companies/{company_id}/{asset}` | Exception | Bare string `{asset}` under an id can be mistaken for a sub-resource or verb; candidate for rename to `.../branding/{asset}` |
| GET | `/public/tenants/{tenant_id}/{asset}` | Exception | Bare string `{asset}` under an id can be mistaken for a sub-resource or verb; candidate for rename to `.../branding/{asset}` |
| GET | `/public/contact-sync/google/callback` | Exception | OAuth redirect URI registered with the provider; a rename needs a provider-side update |
| GET | `/public/contact-sync/microsoft/callback` | Exception | OAuth redirect URI registered with the provider; a rename needs a provider-side update |
| GET | `/public/invoice-issuer/{provider}/callback` | Exception | OAuth redirect URI registered with the provider; a rename needs a provider-side update |

### Contact tree

Mounted at `/api/v1/contact`. Contact Bearer. Paths below are relative to `/api/v1`.

| Methods | Path | Class | Note |
| --- | --- | --- | --- |
| PUT/DELETE | `/contact/companies/self/{asset}` | Exception | Bare string `{asset}` under an id can be mistaken for a sub-resource or verb; candidate for rename to `.../branding/{asset}` |
| POST | `/contact/auth/login` | Conforming |  |
| POST | `/contact/auth/refresh` | Conforming |  |
| POST | `/contact/auth/logout` | Conforming |  |
| POST | `/contact/auth/set-password` | Conforming |  |
| POST | `/contact/auth/login-link` | Conforming |  |
| POST | `/contact/auth/login-link/redeem` | Conforming |  |
| GET/PUT | `/contact/auth/me` | Conforming |  |
| PUT | `/contact/auth/me/password` | Conforming |  |
| POST | `/contact/auth/me/mfa/setup` | Conforming |  |
| POST | `/contact/auth/me/mfa/enable` | Conforming |  |
| POST | `/contact/auth/me/mfa/disable` | Conforming |  |
| GET | `/contact/auth/me/sessions` | Conforming |  |
| DELETE | `/contact/auth/me/sessions/{session_id}` | Conforming |  |
| GET/PATCH | `/contact/companies/self/branding` | Conforming |  |
| POST | `/contact/access-requests` | Conforming |  |
| GET | `/contact/dashboard/summary` | Conforming |  |
| GET | `/contact/portal/{handle}/host` | Exception | Pre-login lookup keyed by a public handle or slug; singular `portal` namespace; candidate for rename |
| GET | `/contact/portal/{slug}/resolve-to-portal-id` | Exception | Pre-login lookup keyed by a public handle or slug; singular `portal` namespace; candidate for rename |
| GET/POST | `/contact/payment-methods` | Conforming |  |
| DELETE | `/contact/payment-methods/{id}` | Conforming |  |
| PUT | `/contact/payment-methods/{id}/default` | Conforming |  |

### Signed receivers

Mounted at `/api/v1/bunyip`, `/api/v1/stripe`, `/api/v1/paypal` and `/api/v1/webhooks`. No session; each authenticates by the sender signature. Paths below are relative to `/api/v1`.

| Methods | Path | Class | Note |
| --- | --- | --- | --- |
| POST | `/bunyip/oauth2/backchannel-logout` | Exception | OIDC-defined logout endpoint; authenticated by the logout token signature, not a session |
| POST | `/bunyip/webhooks/account-deleted` | Exception | Signed receiver: path fixed by the sender configuration; authenticates by signature, not a session |
| POST | `/bunyip/webhooks/mokosh-grant-changed` | Exception | Signed receiver: path fixed by the sender configuration; authenticates by signature, not a session |
| POST | `/stripe/webhooks/{tenant_id}` | Exception | Signed receiver: path fixed by the sender configuration; authenticates by signature, not a session |
| POST | `/paypal/webhooks/{tenant_id}` | Exception | Signed receiver: path fixed by the sender configuration; authenticates by signature, not a session |
| POST | `/webhooks/xero` | Exception | Signed receiver: path fixed by the sender configuration; authenticates by signature, not a session |
| POST | `/webhooks/quickbooks` | Exception | Signed receiver: path fixed by the sender configuration; authenticates by signature, not a session |
