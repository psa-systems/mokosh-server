# Billing

Mokosh owns invoices, quotes, payments, credit notes, statements, tax rates, prepaid blocks, and the hooks into Xero and QuickBooks that let it hand issuing off to the client's accounting system.

## The model

- **Invoice**: a receivable addressed to a client, built from time entries, products, or free-form lines. Its lifecycle is `draft` -> `sent` -> `paid`, with side arcs to `void` (through amendment) and overdue.
- **Quote**: a pre-sale document that becomes an invoice on acceptance. Quotes carry their own approval chain.
- **Credit note**: a reversal issued against a sent invoice.
- **Statement**: a read model summing a company's balance as of today. Nothing is stored for it.
- **Payment**: an inbound credit, either through a connected gateway (Stripe, PayPal) or recorded manually.
- **Tax rate**: a tenant-scoped percentage applied to lines.

## Billable time

A time entry is armed for billing at creation, not at approval. When a technician logs time against a client ticket, the entry's billing status becomes `ready_to_bill` immediately, provided the rules (contract, rate card, work type, non-billable flag) allow it. Creating the invoice sweeps every `ready_to_bill` entry for the client.

This is why a tenant with the Timesheets feature off can still invoice: timesheet submission and approval only unlock the approval step; they do not gate billability. An entry marked non-billable, through the entry's own flag, carries that state through to the invoice and does not bill.

An update to a time entry re-resolves billing status, so switching a billed line between billable and non-billable does the right thing on the next invoice; already-billed entries stay billed.

## Tax

Tax derives from the tenant's configured tax rate, applied uniformly to invoices and quotes. A rate changes future documents; it does not retrospectively re-tax sent invoices.

A line can mark itself tax-exempt, and the invoice total adjusts accordingly. The exemption is per line, not per invoice.

Multiple tax rates can coexist on a tenant (region, product type), with the default rate applied unless a line names another.

## Totals have one writer

Every money total an invoice, quote or credit note displays comes from one service calculation that reads the row's lines and tax rate and emits subtotal, tax, discount and total. No handler patches a total directly; no template recomputes it. This is why editing a line always updates the header total correctly.

## Delegated issuing (Xero, QuickBooks)

A tenant can connect Xero or QuickBooks to hand off invoice issuing. When delegation is on for a company:

- Mokosh issues the invoice to its own ledger as usual.
- On `send`, the invoice is enqueued for delivery to the chosen provider.
- The provider's webhook reports back when the invoice has been accepted, sent to the customer, or paid.
- Mokosh's status reflects the provider's status for the delegated side of the lifecycle.

A delegated invoice still carries Mokosh's issuer snapshot, line items and PDF; the provider gets a mirror of what Mokosh sent. Payment recorded in the provider flows back through the webhook to mark Mokosh's invoice paid.

Setting up delegation is operator-gated: the OAuth client lives at the deployment, not at the tenant. See [operations/delegated-invoicing.md](operations/delegated-invoicing.md).

## Sent means it went

`sent` is set only after the outbound mail has been handed to the SMTP relay without error. A failed send keeps the invoice in `draft`, so the operator sees it has not actually been delivered.

An invoice can also be marked sent manually without emailing it, for a case where the client has been handed the PDF through another channel. The audit trail records which path set the status.

## Due date defaults from net terms

An invoice's default due date is set from the tenant's net-terms policy (`net_days`). An admin can override the due date per invoice, which the mail copy picks up. A dateless invoice is not permitted; the server refuses to send one.

## Overdue is derived, reminders are a worker

An invoice is overdue when today's date exceeds the due date and the invoice is not yet paid. There is no `overdue` status column; the derivation is cheap enough to do at read time.

A background worker scans overdue invoices periodically and sends reminders based on the tenant's reminder cadence. The reminder is a notification; sending one does not change the invoice state.

## Prepaid blocks

A client can prepay for a block of hours at a negotiated rate. Logged time against the block draws it down. When the block is exhausted:

- Remaining hours on the ticket bill at the block's hourly rate (overage), which may differ from the tenant's default rate.
- Unused hours at period close roll over to the next period, unless the block's terms say otherwise.

The block's definition carries its hourly rate, start and end dates, rollover rule and roll-forward cap. The block contract is a separate record from the invoices it anchors; invoices for the block period reference it.

## Write-off is not a credit

Writing an invoice off removes it from receivables without generating a credit for the client. Use a write-off when the amount is uncollectable and the business decision is to stop pursuing it; use a credit note when you owe the client a reduction they can apply to a future invoice. The audit trail distinguishes them.

## Quote approval

A quote is approved by its chain (named by the quote on creation) or by hand when no chain is configured. The chain carries ordered steps; each step is an admin or a named user. A quote with no chain can be approved directly by an admin.

Approval moves the quote to `accepted` and unlocks the "convert to project / invoice" action. Rejection is final; the quote cannot be re-approved without a new version.

## Currency

Every invoice uses the tenant's configured currency. Mokosh does not currently support multi-currency billing within one tenant. Changing the tenant currency changes future invoices; sent invoices keep the currency they were issued in.

## Who reads what

- Reading billing data (invoices, quotes, payments, credit notes) requires both the Billing module enabled on the tenant AND the Finance role (or Admin) on the user.
- The contact plane reads a company's invoices on the portal when the contact's capability set grants it. A contact cannot read another company's invoices.
- Writing billing data (creating an invoice, recording a payment, approving a quote) requires Admin or Finance.

A technician with no billing role sees no billing panes and cannot reach the endpoints; they answer 403.
