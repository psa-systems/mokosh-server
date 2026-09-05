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

Because the status transition to `void` also flows through `update_invoice`, this guard means voiding is only possible while the invoice is still `draft` or `pending`. A `sent` invoice cannot be edited, cannot be cancelled, and cannot be voided through this path.

## What each state can do

- `draft` / `pending` (editable): edit header and lines, Send (-> `sent`, subject to the recipient precondition below), or Void (-> `void`). Void here is the pre-send back-out: it preserves the row for audit instead of deleting it.
- `sent` / `partially_paid` (collectible): the only action is Record Payment, which runs through `record_payment` (a separate path, not `update_invoice`) and advances the status `sent` -> `partially_paid` -> `paid` as the balance is collected.
- `paid` / `void` / `written_off` (terminal): no further lifecycle actions.

## Overdue and reminders (PMS-1037)

Overdue is derived on every read, never stored: `is_overdue` and `days_overdue` on `InvoiceResponse` are `status IN ('sent', 'partially_paid') AND balance_due > 0 AND due_date < today`, computed in the tenant's day (`read_tenant_zone`, PMS-1030), and `GET /invoices?overdue=true` filters on the same predicate. A stored flag would be a second home for a fact `due_date` and `balance_due` already hold, and the only one that could be stale.

Reminders are a worker. `InvoiceReminderWorker` runs hourly; for each tenant with `billing_reminders/enabled` and a `schedule` (day offsets such as `[3, 7, 14, 30]`), at the tenant's local `send_hour` (default 8), it mails every overdue invoice whose `days_overdue` equals a step, to the address the invoice was emailed to (PMS-992) else the resolved billing contact (PMS-993), with the stored document attached (PMS-959) and the pay link when a gateway is connected. `invoice_reminders` records each send per invoice per step and is the idempotency guard, so a run that fires twice in the hour sends once; a refused send releases the claim so the next run tries again. Late fees are deliberately not here: a fee is a new line on a new document, and its own ticket.

## Sending requires a recipient

PMS-993. An invoice cannot reach `sent` without a `billing_contact_id`, because an issued invoice with no recipient is a document nobody was ever asked to pay. The recipient is the company's billing contact, `companies.default_billing_contact_id`: per-company and single-valued, so reassigning it replaces the previous holder.

`update_invoice` settles it on the first `draft`/`pending` -> `sent` transition. If the invoice already carries a `billing_contact_id` it is used; otherwise the company's billing contact is resolved and WRITTEN to the invoice in the same statement. If neither yields one, the transition is refused with a 409 and the invoice stays editable.

Two properties matter and both are pinned by tests:

- The refusal is total. It runs before the issuer snapshot is frozen (PMS-911) and before the issued document is stored (PMS-959), so a refused send leaves `sent_at` NULL, `issuer_snapshot` NULL and no `files` row of `entity_type = 'invoice_document'`. There is no half-sent state to clean up.
- The resolved recipient is persisted, not merely checked. The pay-now email (PMS-711) reads `invoices.billing_contact_id` after the commit, so an invoice that passed the guard without storing what it resolved would freeze, issue a document, and still email nobody.

The three create paths (`create_invoice`, `create_invoice_from_time_entries`, and the recurring sweep's `generate_one_recurring_invoice`) also fall back to the company's billing contact when the request names none, so a draft usually carries its recipient from the moment it exists. An explicitly supplied `billing_contact_id` is validated against the invoice's company and tenant and is a 400 otherwise: FK checks bypass RLS, so nothing else was stopping a cross-account link.

Operationally: a company with no billing contact produces drafts that cannot be sent. `CompanyResponse.default_billing_contact_id` is what makes that visible before someone tries. The recurring sweep logs a warning naming the company when it creates a draft it knows cannot be sent.

## Why a sent invoice is immutable

Once an invoice is sent, the customer holds a copy and can quote the totals back. Mutating or deleting it would break audit integrity and invite fraud. Standard accounting practice keeps issued documents on the record and corrects them with a follow-on document, not by editing or deleting the original. Correcting a sent invoice therefore belongs to a credit note flow, which is not yet built (tracked separately). Until then, a sent invoice that should not have been issued stays on record; its balance is simply never collected.

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
