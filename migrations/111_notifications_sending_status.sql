-- PMS-782: the dispatcher no longer delivers inside its claiming transaction.
--
-- A tick now claims its batch by flipping the rows to 'sending' (bumping
-- attempt_count and stamping next_attempt_at = NOW() + the claim timeout),
-- commits, sends with nothing open, then writes the outcomes back. 'sending'
-- is that claimed-but-unresolved state and has to be legal in the status
-- domain.
--
-- Crash recovery reuses next_attempt_at rather than adding a column: a row
-- still 'sending' after its next_attempt_at has passed belonged to a worker
-- that died mid-tick, and is due again on the same predicate as a 'pending'
-- row. The dispatcher's claim query therefore reads both statuses, which the
-- old pending-only partial index cannot serve.

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_status_check;

ALTER TABLE notifications
    ADD CONSTRAINT notifications_status_check
    CHECK (status IN ('pending', 'sending', 'sent', 'delivered', 'failed'));

DROP INDEX IF EXISTS idx_notifications_pending_due;

CREATE INDEX IF NOT EXISTS idx_notifications_claimable
    ON notifications (next_attempt_at)
    WHERE status IN ('pending', 'sending');
