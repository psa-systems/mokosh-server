# Invoice lifecycle: status model and void-vs-cancel

PMS-580. Explains the invoice status lifecycle, why a sent invoice cannot be edited or cancelled, and what "void" means here. The behavior is intended; this document removes the ambiguity that the smoke test (PMS-560) surfaced.

## Statuses

The seven statuses are defined in `src/modules/billing/models.rs` (`InvoiceStatus`) and the `invoices.status` CHECK constraint in `migrations/010_billing.sql`:

`draft`, `pending`, `sent`, `paid`, `partially_paid`, `void`, `written_off`.

There is deliberately no `cancelled` status. An invoice is either a working draft (mutable) or an issued financial document (immutable). Backing one out is "void", not "cancel".

## Editable vs frozen

`InvoiceStatus::is_frozen()` (`models.rs`) returns true for `sent`, `paid`, `partially_paid`, `void`, and `written_off`. Only `draft` and `pending` are editable.

`InvoiceService::update_invoice` (`src/modules/billing/service.rs`) is the single mutation path for the header, line items, and the status field. Its first guard rejects any change once the invoice is frozen:

```
if current.status.is_frozen() {
    return Err(Conflict("Invoice in status '...' cannot be edited"));
}
```

Voiding is bounded the same way, and since PMS-1333 it has its own endpoint rather than a status on this PUT (see "Voiding" below): a `sent` invoice cannot be edited, cannot be cancelled, and cannot be voided.

## What each state can do

- `draft` / `pending` (editable): edit header and lines, Send (-> `sent`, subject to the recipient precondition below), or Void (`POST /invoices/{id}/void`, PMS-1333). Void here is the pre-send back-out: it preserves the row for audit instead of deleting it.
- `sent` / `partially_paid` (collectible): Record Payment, which runs through `record_payment` (a separate path, not `update_invoice`) and advances the status `sent` -> `partially_paid` -> `paid` as the balance is collected; Credit (a credit note, PMS-953); or Write off (PMS-1036, below).
- `paid` / `void` / `written_off` (terminal): no further lifecycle actions. A payment recorded against a `written_off` invoice is a recovery: it is kept and the status stands.

## What an invoice number is (PMS-979)

Two schemes, chosen per tenant by `billing_prefs/invoice_numbering`, which is a closed set refused at the write.

`tenant_sequence` is the default and the original: one counter for the whole tenant, `INV-000042`. `company_prefix` is per customer: a four-character prefix, a dash and that customer's own zero-padded sequence, `A7QF-000001`. The default did not change when the second scheme shipped, because an MSP's invoice numbering is an accounting decision and moving every existing tenant onto a new shape mid-year is not something to do on their behalf. What the second scheme buys is that a customer's invoices are visibly theirs and their history reads consecutively, and that the document no longer tells every customer how many invoices the MSP has issued in total.

The prefix is random rather than derived from the company name, for the reason `portal_id` is (migration 174): names collide, names change, and a derived identifier stops being stable the first time a customer rebrands. Its alphabet excludes I, L, O, 0 and 1, so a number read back over the phone cannot become another customer's, which leaves 31 characters and 923,521 prefixes per tenant. It is assigned lazily on the customer's first invoice under this scheme, so a company that is never invoiced never gets one.

Both counters are table rows rather than Postgres sequences, and that is deliberate: a sequence keeps its increment when the transaction that took it rolls back, so a failed create would leave a hole in a customer's numbering, and gap-free is an audit expectation on invoices. A row rolls back with everything else, and concurrent creates queue on it rather than racing.

Switching schemes renumbers nothing. A number is a stored string on the invoice it belongs to, and `invoices.number_scheme` records which scheme produced it (NULL on invoices issued before the column existed), so the next change is a switch as well. The year is deliberately not part of a number: adding it later would restart every customer's sequence each January, which is exactly the renumbering this design avoids.

## Voiding, and what crediting does instead (PMS-1333)

`POST /invoices/{id}/void` with an optional `{ reason }` moves a `draft` or `pending` invoice to `void` and records `voided_at`, `voided_by_id` and `void_reason`. Finance only. Every other status is refused with a 409 that names it and points at the credit note, because past `pending` the customer holds a copy. The reason is optional where the write-off's is required: a draft withdrawn before anyone saw it often has nothing to say. No amount is frozen beside it either, for the same reason: a write-off forgives a debt that was genuinely owed, while a void says nothing was ever owed.

Crediting an invoice does NOT void it. Until PMS-1333, a credit note covering the invoice's full total moved it to `void` (PMS-953 introduced that as the first writer `void` ever had, and PMS-1226 narrowed the threshold after a 5.00 goodwill credit voided a paid invoice). That read a credited invoice as a cancelled one, which it is not: the document stood, the customer holds it, and the credit note is the correction. A credit that takes the balance to zero now lands on `paid`, which is also what Stripe does - "if a credit note reduces the balance of an open invoice to 0, the invoice status changes to paid" ([Stripe: issue credit notes](https://docs.stripe.com/invoicing/dashboard/credit-notes)) - so a tenant reconciling against their gateway sees the same shape on both sides. Such an invoice carries no `paid_at`: nothing is owed and nobody paid.

Two consequences follow from voiding being allowed only pre-send. A voided invoice never appears on a statement (PMS-954), because it was never issued and never owed; a fully credited one still does, beside the credit note that settled it. And a credit note against a voided invoice is refused, because there is no charge to correct.

`voided_at` leads `recompute_invoice_balance`'s status CASE, just ahead of `written_off_at`, so a payment or credit landing afterwards cannot derive the status back over one somebody chose.

## Writing off, distinct from crediting (PMS-1036)

`POST /invoices/{id}/write-off` with `{ reason }` (required) moves a `sent` or `partially_paid` invoice to `written_off` and records `written_off_at`, `written_off_by_id`, `write_off_reason` and `write_off_amount`, the balance at that moment, frozen. Finance only, like every other write to an issued document. `draft` (delete it), `paid`, `void` and `written_off` are refused with a 409 naming the status. There is no reversal.

A credit note says the customer did not owe this and reduces revenue. A write-off says the customer owes it and will not pay: a bad-debt expense. The books treat them differently, so `balance_due` is left exactly as it was (the debt was not forgiven), the online payment path refuses the invoice the way it refuses `void`, and `recompute_invoice_balance` keeps the status standing through any later payment or credit (its status CASE reads `written_off_at` first). The statement (PMS-954) lists a written-off invoice under its own `write_offs` line kind, dated by the write-off and carrying the frozen amount, and takes `total_written_off` out of the closing balance: the customer is no longer asked to settle it, and a period that closed before the write-off is not rewritten by it.

## Overdue and reminders (PMS-1037)

Overdue is derived on every read, never stored: `is_overdue` and `days_overdue` on `InvoiceResponse` are `status IN ('sent', 'partially_paid') AND balance_due > 0 AND due_date < today`, computed in the tenant's day (`read_tenant_zone`, PMS-1030), and `GET /invoices?overdue=true` filters on the same predicate. A stored flag would be a second home for a fact `due_date` and `balance_due` already hold, and the only one that could be stale.

Reminders are a worker. `InvoiceReminderWorker` runs hourly; for each tenant with `billing_reminders/enabled` and a `schedule` (day offsets such as `[3, 7, 14, 30]`), at the tenant's local `send_hour` (default 8), it mails every overdue invoice whose `days_overdue` equals a step, to the address the invoice was emailed to (PMS-992) else the resolved billing contact (PMS-993), with the stored document attached (PMS-959) and the pay link when a gateway is connected. `invoice_reminders` records each send per invoice per step and is the idempotency guard, so a run that fires twice in the hour sends once; a refused send releases the claim so the next run tries again. Late fees are deliberately not here: a fee is a new line on a new document, and its own ticket.

## Creating an invoice does not send it (PMS-978)

Creation makes a draft. Nothing is emailed, nothing is frozen, and no document is stored; the customer learns of the invoice when somebody sends it. That is deliberate rather than missing: an invoice is routinely prepared before it is ready to go out, and the alternative, emailing on create, would need a draft state first to get the same behaviour back.

Sending is the `draft`/`pending` -> `sent` transition on `PUT /invoices/{id}`, and it is the one act that emails the customer, freezes the issuer snapshot (PMS-911) and stores the document (PMS-959). It is also the only place `sent` is written, so the state on the invoice answers "has this gone out" without a second flag: `draft` or `pending` means nobody has been told, `sent_at` says when it went, and `emailed_to` with `emailed_at` says to whom. A send the relay refuses rolls all of it back (PMS-992), so a `sent` invoice is never one nobody received.

Two named audit rows record the delivery itself, beside the whole-row `update` snapshot PMS-117 writes: `invoice.sent` with the address, the contact and the actor, and `invoice.marked_sent` for a `skip_email` send, which records that nobody was emailed on purpose. Without that second one, a deliberate no-email send would be indistinguishable afterwards from a send whose mail was lost, since both leave a `sent` invoice with no `emailed_to`. Both are written inside the send's transaction, so a refusal takes the record away with the transition.

The rows are in `audit_log` and readable through the admin audit-log endpoint, not through the per-record history feed: `HISTORY_ENTITY_TYPES` deliberately excludes billing so a technician cannot browse an invoice's trail.

## Sending requires a recipient

PMS-993. An invoice cannot reach `sent` without a `billing_contact_id`, because an issued invoice with no recipient is a document nobody was ever asked to pay. The recipient is the company's billing contact, `companies.default_billing_contact_id`: per-company and single-valued, so reassigning it replaces the previous holder.

`update_invoice` settles it on the first `draft`/`pending` -> `sent` transition. If the invoice already carries a `billing_contact_id` it is used; otherwise the company's billing contact is resolved and WRITTEN to the invoice in the same statement. If neither yields one, the transition is refused with a 409 and the invoice stays editable.

Two properties matter and both are pinned by tests:

- The refusal is total. It runs before the issuer snapshot is frozen (PMS-911) and before the issued document is stored (PMS-959), so a refused send leaves `sent_at` NULL, `issuer_snapshot` NULL and no `files` row of `entity_type = 'invoice_document'`. There is no half-sent state to clean up.
- The resolved recipient is persisted, not merely checked. The pay-now email (PMS-711) reads `invoices.billing_contact_id` after the commit, so an invoice that passed the guard without storing what it resolved would freeze, issue a document, and still email nobody.

The three create paths (`create_invoice`, `create_invoice_from_time_entries`, and the recurring sweep's `generate_one_recurring_invoice`) also fall back to the company's billing contact when the request names none, so a draft usually carries its recipient from the moment it exists. An explicitly supplied `billing_contact_id` is validated against the invoice's company and tenant and is a 400 otherwise: FK checks bypass RLS, so nothing else was stopping a cross-account link.

Operationally: a company with no billing contact produces drafts that cannot be sent. `CompanyResponse.default_billing_contact_id` is what makes that visible before someone tries. The recurring sweep logs a warning naming the company when it creates a draft it knows cannot be sent.

## Why a sent invoice is immutable

Once an invoice is sent, the customer holds a copy and can quote the totals back. Mutating or deleting it would break audit integrity and invite fraud. Standard accounting practice keeps issued documents on the record and corrects them with a follow-on document, not by editing or deleting the original.

The follow-on document is the credit note, and it is the supported correction for a sent invoice: `POST /api/v1/credit-notes` against the invoice, `GET /api/v1/credit-notes` to list them. The invoice itself is never touched. Its lines, totals and number stay exactly as the customer received them; what changes is its derived balance, because `recompute_invoice_balance` folds issued credit notes into `amount_credited` and `balance_due` alongside payments.

A credit note is issued the moment it is created, so it is immutable in the same way and for the same reason: the customer holds a copy of it too. There is no PUT and no DELETE on it. A credit note raised in error is voided (`POST /api/v1/credit-notes/{id}/void`), which changes no amount and no line and simply stops the credit counting against the invoice, and its own document is stored at creation and served unchanged from `GET /api/v1/credit-notes/{id}/pdf`.

## AC3 decision: no separate pre-send "cancel"

The question of whether `draft` / `pending` invoices need a dedicated "cancel" affordance is answered: no separate control is needed. Void already serves as the pre-send back-out for those states and keeps the row for audit. Adding a second control labelled "Cancel" with the same effect would only confuse. If product later wants the pre-send action relabelled (for example "Cancel" instead of "Void" while still in draft), that is a UI-copy change to scope as its own ticket, not a new status or a logic change.

## Who the document is addressed to

PMS-1001. Every document carries a customer block: "Bill to" on the invoice, "Credit to" on the credit note, "Account" on the statement. Each holds the company's name, its billing address (its postal address when no billing address is on file), and, when one resolves, an `Attn:` line naming the billing contact with their email address beneath. A document with no contact to name prints the company alone: there is no empty labelled line.

Where the contact comes from differs by document, and the difference is the point:

- **Invoice**: `invoices.billing_contact_id`, the invoice's own column. `update_invoice` writes it on the first transition to `sent`, recording whichever contact `resolve_invoice_recipient` picked, so the invoice names the person it was actually emailed to even when that person came from the company's `default_billing_contact_id`. Reassigning the billing role afterwards changes nothing on that invoice.
- **Credit note**: the `billing_contact_id` of the invoice it corrects, so the two documents in one correction name the same person.
- **Statement**: the company's *current* `default_billing_contact_id`. A statement spans many invoices that may each name a different person, and PMS-954 made it a read model that stores nothing, so it renders from today exactly as its issuer and its branding do. Reassigning the role does change the next statement.

Documents issued before this landed are not re-rendered. PMS-959 stores an invoice's PDF inside the transaction that first sends it and a credit note's inside the transaction that creates it, and `GET /invoices/{id}/pdf` and `GET /credit-notes/{id}/pdf` serve those bytes whenever there are any. Only invoices sent and credit notes created after this change carry the contact; an older document keeps the bytes its customer already holds. A live render (a draft preview, or anything issued before PMS-959) does pick the contact up.

## The document template

PMS-1006. `tenants.branding.invoice_template` chooses how a document is laid out: `classic`, `modern` or `compact`. The keys are validated in `src/modules/tenants/branding.rs` against `pdf::Template`, and anything else is refused with a message naming the three. Absent or null is `classic`, which is the output every document had before templates existed, so a tenant that never chooses sees nothing change.

The choice is tenant-wide, not per invoice. An MSP's documents should look alike, and there is no per-invoice override: the bytes of an issued document are what the record is, so a per-invoice field would store a value nothing could read back off the document.

Which documents follow it:

- The invoice, at the moment it is rendered. A draft renders live, so it follows the tenant's current choice; `GET /invoices/{id}/pdf?template=<key>` previews another one on the MSP's own data while the invoice is still editable. The parameter is a staff affordance: PMS-936 opened that route to the contact plane too, and a contact passing it is refused rather than served a layout nobody picked.
- The credit note, at creation, which is when it is issued and when its document is stored (PMS-953, PMS-959).
- The statement, every time, because PMS-954 made it a read model that stores nothing.
- NOT the report export (`GET /reports/{key}/export?format=pdf`). An internal report is not a document a client receives and carries no branding at all; it stays Classic.

An already-sent invoice keeps its stored bytes. PMS-959 writes the rendered PDF inside the transaction that first moves the invoice to `sent`, and `GET /invoices/{id}/pdf` serves those bytes for any frozen invoice, so changing `invoice_template` (or the accent colour, or the legal name) afterwards cannot alter a document a customer already holds. For the same reason `?template=` is a 400 on a frozen invoice rather than a re-render: that path serves what was sent, and there is only one answer to give.

`primary_color` is the accent the Modern template draws its head band in; a tenant that set none gets `pdf::DEFAULT_ACCENT`. The band's own text is dark or light according to the band colour's relative luminance, so a pale brand colour does not produce white on white.

## UI

The invoice detail page (`mokosh-apps`, `src/pages/billing.rs`) mirrors this model: Edit / Send / Void render only while editable (`draft` / `pending`), Record Payment renders only while collectible, and a frozen invoice shows an inline note explaining that it is a finalized record and cannot be edited, cancelled, or voided.

Its Void button still sends `PUT /invoices/{id}` with `{"status":"void"}`, which PMS-1227 made a 422, so voiding a draft has been broken from the client since that landed. Pointing it at `POST /invoices/{id}/void` is MAPPS-937.
