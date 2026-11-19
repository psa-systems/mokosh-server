# Integrations

Mokosh connects to external systems through a shared integrations catalog. Each integration has its own connect flow, its own credentials, and its own list of what breaks when it is offline.

## Bunyip (identity provider)

Bunyip is the sole identity provider for staff users.

- What it does: authenticates every staff sign-in, mints the OIDC access token Mokosh verifies, holds the user directory for grant lookups and mailer relay.
- What to configure: `OIDC_ISSUER`, `OIDC_AUDIENCE`, and (for the directory and grant features) `BUNYIP_API_BASE_URL`, `BUNYIP_DIRECTORY_CLIENT_ID`, `BUNYIP_DIRECTORY_CLIENT_SECRET`. For the Bunyip mailer path, add `BUNYIP_MAILER_URL` and its client credentials and set `MAIL_PROVIDER=bunyip`. See [configuration](configuration.md).
- What breaks if Bunyip is unreachable: every new staff sign-in. Existing sessions keep working until they expire. The contact plane is unaffected (contacts sign in to Mokosh directly).

## Stripe (payments)

Stripe takes payment on an invoice through a Checkout session the customer completes.

- What it does: accepts card and local-payment-method payment on an invoice, then signals Mokosh through a webhook so the invoice marks paid.
- What to configure: `STRIPE_PUBLISHABLE_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`. Create a Stripe webhook endpoint pointing at `/api/v1/stripe/webhook`.
- What breaks if Stripe is unreachable: the "Pay now" button on the portal fails; the invoice stays `sent`. A webhook that arrives late still processes correctly.
- Signature: every Stripe webhook is HMAC-signed. A delivery with a bad signature answers 400 without touching the invoice.

## PayPal (payments)

PayPal takes payment on an invoice through a hosted order.

- What it does: same shape as Stripe, different provider.
- What to configure: `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`. Create a webhook pointing at `/api/v1/paypal/webhook`.
- What breaks if PayPal is unreachable: the PayPal option on the portal fails. An invoice does not retry across providers; the customer chooses another method.

## Xero (delegated invoicing)

Xero takes over invoice issuing and payment tracking for a tenant that keeps its books there.

- What it does: when delegation is on for a company, Mokosh issues the invoice to its own ledger and then hands it to Xero. Xero mails the customer, tracks payment, and webhooks back when the invoice state changes.
- What to configure: a deployment-level Xero OAuth client (`XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `XERO_WEBHOOK_KEY`), then each tenant connects its own Xero organization through the connect flow. Per-company mappings (Mokosh company to Xero customer, Mokosh product to Xero item) are configured on the admin surface. See [operations/delegated-invoicing.md](operations/delegated-invoicing.md).
- What breaks if Xero is unreachable: invoice send to Xero fails; the invoice stays `sent` on the Mokosh side, enqueued for retry. The customer does not receive the invoice until Xero is back.
- Signature: Xero webhooks are HMAC-signed against `XERO_WEBHOOK_KEY`. A deployment without a webhook key refuses to verify deliveries; the operator sees this at startup.

## QuickBooks (delegated invoicing)

QuickBooks is the second delegated-issuing provider.

- What it does: same shape as Xero, different provider.
- What to configure: `QUICKBOOKS_CLIENT_ID`, `QUICKBOOKS_CLIENT_SECRET`, `QUICKBOOKS_VERIFIER_TOKEN`. Per-tenant connect through the connect flow.
- What breaks: same as Xero.
- Signature: QuickBooks deliveries are verified against the verifier token.

## Google Workspace (contact sync)

Google Workspace imports contacts from a staff user's Google address book, filtered by label.

- What it does: polls the user's Contacts, imports records that carry one of the selected labels, and mirrors them onto Mokosh contacts.
- What to configure: a deployment-level Google OAuth client (`GOOGLE_CONTACTS_CLIENT_ID`, `GOOGLE_CONTACTS_CLIENT_SECRET`), then each tenant connects through the contact-sync page. On a hosted deployment with Bunyip's host-secrets endpoint set, the client pair can be read from Bunyip instead, so one operator keystroke covers every tenant.
- What breaks: sync fails for the labeled records; records already imported stay where they are. Contacts moved out of the label stop being updated (they are not tombstoned).
- Floor: minimum sync interval is 5 minutes. Maximum is 24 hours.

## Microsoft 365 (contact sync)

Microsoft 365 contact sync is the Entra ID equivalent of the Google path.

- What it does: imports contacts from a Microsoft 365 account's Contacts folder, filtered by label.
- What to configure: `MICROSOFT_CONTACTS_CLIENT_ID`, `MICROSOFT_CONTACTS_CLIENT_SECRET`. Per-tenant connect through the contact-sync page.
- What breaks: same as Google.

## Infisical (secret storage)

Infisical holds secrets the deployment prefers not to keep in Postgres or the process environment.

- What it does: serves a provider for tenant-tier or application-tier secrets when `SECRET_BACKEND=infisical` or `APP_SECRET_BACKEND=infisical`.
- What to configure: `INFISICAL_HOST`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_PROJECT_ID`. First-run setup of a fresh Infisical instance is driven by `mokosh-bootstrap bootstrap-infisical`.
- What breaks: at startup, a boot that reads a secret from Infisical and cannot reach it refuses to come up. The failure message names Infisical as the provider; the fix is to make Infisical reachable, not to fall back to another provider (the whole point of the provider rule is that a declared provider is never silently replaced).
- Moving a secret to or from Infisical is a documented operator workflow. See [operations/provider-runbook.md](operations/provider-runbook.md).

## Status at a glance

Every integration above surfaces status in one place:

- `GET /api/v1/integrations`: the catalog, with per-capability status (`connected`, `disconnected`, `error`, with the last error message).
- `GET /api/v1/providers/status`: the provider seam report, naming which provider each key is being served from.

The second surface is for operators; the first is for tenant admins.
