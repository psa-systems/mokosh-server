-- PMS-934: the seeded payment terms are identifiers sitting in a display
-- column.
--
-- `payment_terms.name` is the only human-facing string on the row, it is what
-- the invoice form's dropdown renders verbatim, and it is tenant-editable
-- through the Settings hub (MAPPS-170) so an MSP can call its terms whatever it
-- calls them. Migration 050 seeded it with `due_on_receipt`, `net15`, `net30`
-- and `net60`, carried across from the legacy free-text `invoices.payment_terms`
-- string it replaced. That was right for the backfill join and wrong for the
-- dropdown, which is where MAPPS-599 reported it.
--
-- Renaming is safe because nothing resolves a term by name: storage is the
-- normalized FK `invoices.payment_term_id`, which 050 chose for exactly this
-- reason, and the 30-day due-date default is a hardcoded `Duration::days(30)`
-- rather than a lookup. `TenantService::create` copies payment terms from the
-- default tenant row-for-row, so every tenant created after this inherits the
-- readable names with no code change.
--
-- Two guards, both following migration 116's pattern for rewriting seeded copy:
--
--   * each row is matched on the seeded identifier VERBATIM, so a tenant that
--     has already renamed its own term keeps that name and is not silently
--     reworded by an upgrade;
--   * the rename is skipped where the target name already exists for that
--     tenant, because `idx_payment_terms_tenant_name` is unique and 050's own
--     backfill could have inserted a row already called "Net 30" from a legacy
--     free-text value.
--
-- `is_default`, `is_active` and `sort_order` are deliberately untouched: net30
-- stays the default and the dropdown keeps its order.

UPDATE payment_terms p
SET name = v.readable,
    updated_at = NOW()
FROM (VALUES
    ('due_on_receipt', 'Due on receipt'),
    ('net15', 'Net 15'),
    ('net30', 'Net 30'),
    ('net60', 'Net 60')
) AS v(seeded, readable)
WHERE p.name = v.seeded
  AND NOT EXISTS (
      SELECT 1
      FROM payment_terms other
      WHERE other.tenant_id = p.tenant_id
        AND other.name = v.readable
  );
