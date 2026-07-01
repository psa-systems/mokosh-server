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

- `draft` / `pending` (editable): edit header and lines, Send (-> `sent`), or Void (-> `void`). Void here is the pre-send back-out: it preserves the row for audit instead of deleting it.
- `sent` / `partially_paid` (collectible): the only action is Record Payment, which runs through `record_payment` (a separate path, not `update_invoice`) and advances the status `sent` -> `partially_paid` -> `paid` as the balance is collected.
- `paid` / `void` / `written_off` (terminal): no further lifecycle actions.

## Why a sent invoice is immutable

Once an invoice is sent, the customer holds a copy and can quote the totals back. Mutating or deleting it would break audit integrity and invite fraud. Standard accounting practice keeps issued documents on the record and corrects them with a follow-on document, not by editing or deleting the original. Correcting a sent invoice therefore belongs to a credit note flow, which is not yet built (tracked separately). Until then, a sent invoice that should not have been issued stays on record; its balance is simply never collected.

## AC3 decision: no separate pre-send "cancel"

The question of whether `draft` / `pending` invoices need a dedicated "cancel" affordance is answered: no separate control is needed. Void already serves as the pre-send back-out for those states and keeps the row for audit. Adding a second control labelled "Cancel" with the same effect would only confuse. If product later wants the pre-send action relabelled (for example "Cancel" instead of "Void" while still in draft), that is a UI-copy change to scope as its own ticket, not a new status or a logic change.

## UI

The invoice detail page (`mokosh-apps`, `src/pages/billing.rs`) mirrors this model: Edit / Send / Void render only while editable (`draft` / `pending`), Record Payment renders only while collectible, and a frozen invoice shows an inline note explaining that it is a finalized record and cannot be edited, cancelled, or voided.
