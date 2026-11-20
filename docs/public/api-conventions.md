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

