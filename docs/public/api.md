# API

Every route lives under `/api/v1`. The server is a REST API: JSON in, JSON out, standard HTTP status codes, no RPC. Authenticate with a Bearer token on every call except the explicitly public tree.

## Health and version

- `GET /api/v1/health`: returns `{"status":"ok"}` to anyone. A super admin sees `version`, `git_hash`, `build_date` and the current theme source on top.

## Authentication

- `POST /api/v1/auth/login`: legacy email + password login. Returns a JWT and (when the account has enrolled) takes an optional `totp_code`.
- `POST /api/v1/auth/login/approval/{claim_reference}`: polls a held sign-in and returns the JWT once the owner approves it.
- `POST /api/v1/auth/password-reset/request`: begin a password reset. Rate-limited.
- `POST /api/v1/auth/password-reset/complete`: finish it with the emailed token.
- `POST /api/v1/auth/logout`: invalidate the current session.

## Grants (cross-tenant access)

- `GET/POST /api/v1/grants/invitations`: admin lists and sends grant invitations.
- `GET /api/v1/grants/invitations/by-token/{token}`: unauthenticated lookup for a grantee first sight.
- `GET /api/v1/my-grants/invitations`: the grantee's inbox.
- `POST /api/v1/my-grants/leave/{tenant_id}`: a grantee ends their own access to a tenant.

## Users and members

- `GET/POST/PUT/DELETE /api/v1/users`: tenant user CRUD. Admin-gated for writes.
- `GET /api/v1/members`: unified read of tenant users plus cross-account grants. Manager-gated.

## Tenants and teams (multi-tenant builds only)

- `GET/POST/PUT/DELETE /api/v1/tenants`: tenant CRUD. Platform-admin-gated.
- `GET/POST/PUT/DELETE /api/v1/teams`: teams inside the current tenant.
- `GET /api/v1/me/teams`: the caller's own team memberships.

## Platform

- `GET /api/v1/platform/*`: platform-admin surface; distinct JWT typ, distinct credential store, used by a deployment operator rather than a tenant admin.

## Contacts and companies

- `GET/POST/PUT/DELETE /api/v1/contacts/companies/{id}`: company records.
- `GET/POST/PUT/DELETE /api/v1/contacts`: contact records inside those companies.
- `GET /api/v1/contacts/companies/{id}/sites`: a company's physical sites.
- `GET/POST/PUT/DELETE /api/v1/portal-roles`: the capability templates that gate contact portal access.
- `GET/POST /api/v1/contacts/companies/{id}/portal-roles`: company-scoped role assignments for contacts.
- `GET /api/v1/contacts/companies/{id}/documentation`: company documentation feed, composing assets, credentials and KB.

## Branding

- `PUT /api/v1/contacts/companies/{id}/branding/*`: logo, favicon and background uploads. Staff-admin-gated.

## Tickets

- `GET/POST/PUT/DELETE /api/v1/tickets`: ticket CRUD. Dual-plane.
- `GET/POST/PUT /api/v1/tickets/{id}/notes`: ticket notes. Dual-plane; contact notes are visible to the contact, internal notes are not.
- `POST /api/v1/tickets/{id}/attachments`: attachment upload. Dual-plane; subject to `ATTACHMENT_MAX_BYTES`.
- `POST /api/v1/tickets/{id}/approvals/request`: start an approval chain.
- `GET/POST /api/v1/approvals`: tenant approvals queue.
- `GET /api/v1/contacts/{id}/notes`: cross-ticket feed of notes by one contact.

## Time tracking

- `GET/POST/PUT/DELETE /api/v1/time-entries`: time entry CRUD.
- `POST /api/v1/time-entries/{id}/approvals`: approve or reject a time entry. Gated by the Timesheets feature.
- `GET/POST/PUT /api/v1/timesheets`: weekly timesheet build, submit, approve. Gated by the Timesheets feature.
- `GET/POST /api/v1/work-days`: work-day segments and totals.
- `GET/POST /api/v1/timers`: start, stop, read running timers.
- `GET/POST/PUT/DELETE /api/v1/work-types`: billable or non-billable work categories.
- `GET/POST/PUT/DELETE /api/v1/mileage-entries`: mileage entries.

## Projects

- `GET/POST/PUT/DELETE /api/v1/projects`: projects.
- `GET/POST/PUT/DELETE /api/v1/projects/{id}/phases`: phases.
- `GET/POST/PUT/DELETE /api/v1/projects/{id}/tasks`: tasks with dependencies.
- `GET/POST/PUT /api/v1/task-statuses`: per-tenant task status values.

## Calendar and dispatch

- `GET/POST /api/v1/calendar/*`: events, appointments, availability.
- `GET /api/v1/dispatch`: the scheduling board aggregating appointments, availability and on-call for a date range.
- `GET/POST /api/v1/time-off`: time-off requests.
- `GET/POST /api/v1/on-call`: on-call coverage.

## Contracts and SLA

- `GET/POST/PUT/DELETE /api/v1/contracts`: client contracts.
- `GET/POST /api/v1/contracts/{id}/items`: line items.
- `GET /api/v1/contracts/{id}/balances`: hour and dollar balances.
- `GET/POST/PUT/DELETE /api/v1/sla-policies`: SLA policies.
- `GET/POST /api/v1/sla-targets`: per-ticket SLA target evaluation.
- `GET /api/v1/business-hours`: tenant business hours.

## Billing

- `GET/POST/PUT/DELETE /api/v1/invoices`: invoices. Dual-plane.
- `GET /api/v1/invoices/{id}/pdf`: rendered invoice PDF.
- `POST /api/v1/invoices/{id}/send`: send the invoice by email; records that the mail went.
- `POST /api/v1/invoices/{id}/pay`: contact-plane payment initiation.
- `GET/POST/PUT/DELETE /api/v1/payments`: payment records.
- `GET/POST/PUT /api/v1/payment-gateways`: tenant-configured gateways (Stripe, PayPal, manual).
- `GET/POST /api/v1/credit-notes`: credit notes.
- `GET/POST /api/v1/statements`: customer statements.
- `GET/POST/PUT/DELETE /api/v1/tax-rates`: tax rates.
- `GET/POST/PUT/DELETE /api/v1/quotes`: quotes.
- `POST /api/v1/quotes/{id}/approve`: approve a quote through its chain.
- `GET/POST/PUT/DELETE /api/v1/invoice-issuer-mappings`: Mokosh-to-Xero or Mokosh-to-QuickBooks mappings for delegated invoicing.

## Expenses (inbound money)

- `GET/POST/PUT/DELETE /api/v1/vendors`: vendor records.
- `GET/POST/PUT/DELETE /api/v1/expense-categories`: expense categories.

## Assets

- `GET/POST/PUT/DELETE /api/v1/assets`: asset CRUD.
- `GET/POST/PUT/DELETE /api/v1/asset-types`: asset type definitions.
- `GET/POST /api/v1/asset-catalog`: typeahead catalog for assets. Gated by the Assets Catalog feature.
- `POST /api/v1/assets/{id}/report-issue`: create a ticket linked to an asset.
- `GET /api/v1/credentials`: credential vault entries.

## Knowledge base

- `GET/POST/PUT/DELETE /api/v1/kb/articles`: articles. Dual-plane.
- `POST /api/v1/kb/articles/{id}/render`: render an article with template variables substituted.
- `GET/POST /api/v1/kb/articles/{id}/versions`: version history.
- `POST /api/v1/kb/articles/{id}/versions/{n}/restore`: restore a past version. Manager-gated.
- `GET/POST/PUT/DELETE /api/v1/kb/articles/{id}/comments`: comments on an article. Staff-plane only.
- `GET/POST/PUT/DELETE /api/v1/kb/categories`: categories.
- `POST /api/v1/kb/articles/{id}/attachments`: image uploads for an article.

## Notifications

- `GET /api/v1/notifications/inbox`: the caller's inbox.
- `GET/POST/PUT /api/v1/notifications/preferences`: per-user preferences.
- `GET/POST/PUT/DELETE /api/v1/notifications/templates`: tenant templates. Admin-gated.
- `GET/POST/PUT/DELETE /api/v1/notifications/channels`: delivery channels.
- `GET/POST/PUT/DELETE /api/v1/notifications/rules`: event rules.

## Integrations

- `GET /api/v1/integrations`: the integrations catalog with per-capability status.
- `POST /api/v1/integrations/{name}/connect`: start a connect flow.
- `POST /api/v1/integrations/{name}/disconnect`: tear it down.
- `GET /api/v1/integrations/contact-sync/*`: Google and Microsoft 365 contact sync connect and schedule.
- `POST /api/v1/integrations/xero/connect`, `/quickbooks/connect`: delegated-invoicing connect flows.

## RMM and status

- `POST /api/v1/rmm/alerts`: HMAC-authenticated alert ingest. Not a session.
- `GET/POST/PUT/DELETE /api/v1/rmm/connections`, `/device-mappings`, `/alert-rules`.
- `GET /api/v1/status/monitored-systems`: monitored systems and the last check outcome for each.

## Opportunities

- `GET/POST/PUT/DELETE /api/v1/opportunities`: CRM opportunities, link to quotes.

## Reports

- `GET /api/v1/reports/*`: dashboard, tickets, time, billing, CSV export.
- `GET/POST/PUT/DELETE /api/v1/saved-reports`: saved report definitions.
- `GET/POST/PUT/DELETE /api/v1/dashboards`: per-user saved dashboards.

## Workflow and templates

- `GET/POST/PUT/DELETE /api/v1/workflow-rules`: workflow automation CRUD.
- `GET /api/v1/tickets/{id}/workflow-runs`: timeline of workflow runs on a ticket.
- `GET/POST/PUT/DELETE /api/v1/ticket-templates`: new-ticket pre-fills.
- `GET/POST/PUT/DELETE /api/v1/forms`: form definitions.
- `POST /api/v1/forms/{slug}/submit`: validated submission.

## Settings

- `GET/PUT /api/v1/settings`: tenant settings.
- `GET/PUT /api/v1/settings/email`: deployment-operator SMTP relay.
- `GET/PUT /api/v1/settings/app-name`: deployment-operator product name.
- `GET/PUT /api/v1/settings/google-contacts-client`: deployment-operator Google OAuth client pair.
- `GET /api/v1/settings/feature-toggles`: every registered feature with state. Operator-only.
- `PUT /api/v1/settings/feature-toggles/{key}`: flip one feature. Operator-only.

## Audit and search

- `GET /api/v1/audit-log`: audit log read.
- `GET /api/v1/search?q=`: cross-entity tenant-scoped search.
- `GET /api/v1/ip-enrich?ip=`: advisory ASN / VPN lookup. Admin-gated.

## Data transfer

- `POST /api/v1/data-transfer/export`: tenant data export. Admin-gated.
- `POST /api/v1/data-transfer/import`: bounded import.
- `POST /api/v1/data-transfer/demo-seed`: load the demo dataset.

## Email intake

- `POST /api/v1/email-intake`: inbound email-to-ticket. Authenticates via a tenant intake bearer, not the user auth layer.

## Public tree

Everything under `/api/v1/public/*` is unauthenticated by design.

- `GET /api/v1/public/config`: the feature-toggle probe, booleans only.
- `GET /api/v1/public/branding`: public tenant branding for signed-out pages.
- `GET /api/v1/public/kb/*`: public knowledge base articles.

Per-IP rate limit on this whole nest from `PUBLIC_API_PER_MIN`.

## Contact plane

Everything under `/api/v1/contact/*` is contact-bearer-gated. A contact bearer reaches these routes plus the dual-plane routes above.

## Webhooks

- `POST /api/v1/stripe/webhook`: Stripe signed delivery. Signature-verified; a bad signature is 400.
- `POST /api/v1/paypal/webhook`: PayPal signed delivery.
- `POST /api/v1/bunyip/backchannel-logout`: Bunyip back-channel logout token.
- `POST /api/v1/bunyip/webhook`: other Bunyip events.
- `POST /api/v1/invoice-issuers/xero/webhook`, `/quickbooks/webhook`: delegated-invoicing webhooks.

## Error shape

Every 4xx and 5xx response returns the envelope `{"error":{"code":"...","message":"..."}}`. Code strings are stable for a release and stable by meaning across releases.
