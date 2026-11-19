-- `outcome` gains a sixth value, `benign_redelivery`, for a delivery whose
-- payment a prior delivery already recorded. Before this it read `ignored`,
-- which lumped an idempotent redelivery in with an unrelated event, so the
-- operator-visible log could not separate redundant deliveries from noise.
--
-- The column was VARCHAR(16) and the new value is 17 characters, so the type
-- widens in the same statement as the CHECK. The earlier five values are
-- migrations 213's and 257's, immutable, and stay exactly as they were.
ALTER TABLE payment_webhook_deliveries
    DROP CONSTRAINT payment_webhook_deliveries_outcome_check,
    ALTER COLUMN outcome TYPE VARCHAR(32),
    ADD CONSTRAINT payment_webhook_deliveries_outcome_check CHECK (
        outcome IN ('accepted', 'refused', 'ignored', 'failed', 'unreconciled', 'benign_redelivery')
    );
