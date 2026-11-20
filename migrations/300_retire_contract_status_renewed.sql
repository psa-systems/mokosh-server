-- `renewed` is retired: the lifecycle sweep renews in place and keeps the row `active`.
-- Refuse to narrow the CHECK while any legacy row still carries the value.
DO $$
DECLARE legacy_count int;
BEGIN
  SELECT count(*) INTO legacy_count FROM contracts WHERE status = 'renewed';
  IF legacy_count > 0 THEN
    RAISE EXCEPTION 'contracts.status still has % rows with value renewed; run the expire_due_contracts sweep first', legacy_count;
  END IF;
END $$;

ALTER TABLE contracts DROP CONSTRAINT contracts_status_check;
ALTER TABLE contracts ADD CONSTRAINT contracts_status_check
    CHECK (status IN ('draft', 'active', 'expired', 'cancelled'));
