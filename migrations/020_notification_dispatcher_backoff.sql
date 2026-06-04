-- Backoff bookkeeping for the notifications dispatcher worker.
--
-- attempt_count: how many times the worker has tried to send this row.
-- next_attempt_at: the earliest time the worker may try again. NULL means
--                  "ready now" (newly inserted, no retry yet). Rows whose
--                  next_attempt_at is in the future are skipped by the
--                  worker's SELECT FOR UPDATE SKIP LOCKED query.
--
-- The worker bumps attempt_count + sets next_attempt_at via the backoff
-- ladder (1m, 5m, 30m, 2h, 6h) on transient failures, then flips the row
-- to status='failed' after the 5th attempt.

ALTER TABLE notifications
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_notifications_pending_due
    ON notifications (status, next_attempt_at)
    WHERE status = 'pending';
