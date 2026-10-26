# Turning on delegated invoicing (Xero, QuickBooks)

Delegating Invoicing means the provider issues the invoice your customer receives: it numbers it, it
delivers it, and it records the payment. Mokosh keeps a copy for history and reconciliation and stops
being the system of record for the document (MAPPS-1099).

**Four things have to be true before one invoice is issued externally.** Three are the operator's and
one is the tenant admin's, and the card on `Settings > Integrations > Xero` tells you which one you are
missing:

| | What | Who | What it looks like when missing |
|---|---|---|---|
| 1 | The deployment holds the application's client id and secret | operator | "This deployment has no Xero application configured" |
| 2 | Delegated issuing is switched ON for the deployment | operator | the card says the provider is connected and issuing nothing |
| 3 | The tenant has connected the organisation | tenant admin | "Not connected", with a Connect button |
| 4 | Each client is mapped to a customer in the provider | tenant admin | creating an invoice is refused, naming the company |

Steps 1 and 2 are independent and can be done in either order. Nothing issues externally until all four
hold.

## 1. Register the application, once per deployment

The application is the DEPLOYMENT's, not a tenant's, for the reasons
[PMS-1430](invariants/config-providers.md#google-client-pms-1340) gives for the Google client: a
tenant-owned app costs every MSP a developer-console walkthrough, and an unverified one is capped and
warned about.

Register one Xero app and one Intuit app. Each needs two addresses from this deployment, both derived
from `PUBLIC_API_BASE_URL`:

- **Redirect URI**, which the consent screen returns to:
  `https://<PUBLIC_API_BASE_URL>/api/v1/public/invoice-issuer/xero/callback`
  (and `.../quickbooks/callback`). It has to match byte for byte: the token exchange repeats it, and a
  deployment that changes `PUBLIC_API_BASE_URL` while a consent screen is open gets a refusal.
- **Webhook URL**, if you want Mokosh to hear about payments:
  `https://<PUBLIC_API_BASE_URL>/api/v1/webhooks/xero` (and `.../quickbooks`). One URL per provider for
  the whole deployment, not one per tenant: the subscription belongs to the application, and the
  delivery names the organisation it is about (MAPPS-1141).

## 2. Set the secrets

Six governed application-tier secrets, served by whichever provider `APP_SECRET_BACKEND` names. They are
never read from `.env`.

| Secret | Required | Without it |
|---|---|---|
| `XERO_CLIENT_ID` | pair | no tenant can connect Xero |
| `XERO_CLIENT_SECRET` | pair | as above |
| `XERO_WEBHOOK_KEY` | no | deliveries are refused, so an invoice Xero marks paid stays outstanding here |
| `QUICKBOOKS_CLIENT_ID` | pair | no tenant can connect QuickBooks |
| `QUICKBOOKS_CLIENT_SECRET` | pair | as above |
| `QUICKBOOKS_VERIFIER_TOKEN` | no | as the Xero key, for QuickBooks |

**Setting one half of a client pair without the other refuses the boot**, naming the missing half. That
is deliberate: a host connecting as half an application fails at the provider with an error nobody can
place.

From a shell, one at a time, with the value in the environment rather than in an argument:

```nu
with-env { XERO_ID: "..." } { mokosh-server provider-set --secret XERO_CLIENT_ID --from-env XERO_ID }
```

An application-tier secret is read once at boot, so **restart the server afterwards**. `mokosh-server
provider-status` lists every governed secret and which provider answers for it; the six appear there
whether or not they are set.

## 3. Switch delegated issuing on

The deployment toggle is `delegated_invoice_issuer`, and it is OFF on every deployment until somebody
flips it ([feature toggles](../feature-toggles.md)):

```
PUT /api/v1/settings/feature-toggles/delegated_invoice_issuer   {"enabled": true}
```

Deployment-operator only. It takes effect immediately in the process that served the `PUT` and within
sixty seconds in its siblings.

With the toggle off, a tenant can still connect and map clients, and every invoice is still issued by
Mokosh. The settings card says so rather than claiming otherwise (MAPPS-1154).

## 4. What the tenant admin does

On `Settings > Integrations > Xero`:

1. **Connect.** Opens the provider's consent screen and comes back having authorised ONE organisation. A
   grant covering several is refused rather than guessed at, with copy saying to re-consent for one.
2. **Map the clients.** Each Mokosh company names the customer it is in the provider. An invoice for an
   unmapped company is refused, naming the company. QuickBooks also needs a product on every line, and
   each product mapped to an item, because a QuickBooks line carries an `ItemRef`.

From then on a new invoice for a mapped client is created in the provider, and the local row carries the
provider's own number beside Mokosh's.

## Turning it off

**Disconnect** on the provider's page forgets the credential and stops delegating; invoices the provider
already issued stay where they are, and what was delegated is remembered for a reconnect.

**Flipping the toggle off** stops delegation for every tenant at once and leaves their connections
alone.

Neither withdraws an invoice the provider has already issued. That document is the customer's and it is
the provider's to amend.
