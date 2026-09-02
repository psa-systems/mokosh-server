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

## UI

The invoice detail page (`mokosh-apps`, `src/pages/billing.rs`) mirrors this model: Edit / Send / Void render only while editable (`draft` / `pending`), Record Payment renders only while collectible, and a frozen invoice shows an inline note explaining that it is a finalized record and cannot be edited, cancelled, or voided.
