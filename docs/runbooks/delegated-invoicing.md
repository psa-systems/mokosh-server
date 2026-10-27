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
[PMS-1430](../invariants/config-providers.md#google-client-pms-1340) gives for the Google client: a
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

## Delegating bills, which is a different switch

Delegating Invoicing pushes what your customers owe you. Delegating Bills and expenses pushes what you
owe your vendors, and it is deliberately a separate decision (MAPPS-1155): an MSP can keep invoicing in
Mokosh and still want its payables in the accountant's ledger, or the reverse.

Two gates, mirroring 2 and 3 above:

```
PUT /api/v1/settings/feature-toggles/delegated_bills   {"enabled": true}
```

and, on the tenant's side, the **Bills and expenses** capability enabled on the provider's integration
row. Both plus a connected organisation, and a new bill is raised in the provider; any one missing and
the bill is written locally exactly as before, with `external_provider` and `external_bill_id` left
NULL. The application secrets and the connection from steps 1 to 3 are the same ones; there is nothing
further to register.

What the tenant admin maps:

| Provider | Mapping | Route | Without it |
|---|---|---|---|
| Xero, QuickBooks | each vendor to the vendor over there | `PUT /api/v1/invoice-issuer-mappings/vendors/{provider}/{vendor_id}` | creating a bill is refused, naming the vendor |
| QuickBooks only | each expense category to a ledger account | `PUT /api/v1/invoice-issuer-mappings/expense-accounts/quickbooks/{category_id}` | creating a bill is refused, naming the category |

QuickBooks needs the account because every bill line it accepts carries an `AccountRef`, and nothing
else in Mokosh can say which account an MSP's own books put a cost in. A line with no expense category
at all is refused for the same reason, naming the line. Xero takes the account from the contact, so a
Xero-only tenant maps vendors and nothing more.

Two things delegated bills does NOT do. A delegated bill is still created `draft` in Mokosh, because
approving a bill is the MSP's own step and the provider holding a copy does not change who signs it off.
And payment of a bill is not mirrored back: the invoice webhooks (MAPPS-1136) report what a customer
paid you, and no receiver reads a vendor payment yet, so a bill paid in the provider stays open in
Mokosh until somebody records it here.

## Turning it off

**Disconnect** on the provider's page forgets the credential and stops delegating; invoices the provider
already issued stay where they are, and what was delegated is remembered for a reconnect.

**Flipping the toggle off** stops delegation for every tenant at once and leaves their connections
alone.

Neither withdraws an invoice the provider has already issued. That document is the customer's and it is
the provider's to amend.
