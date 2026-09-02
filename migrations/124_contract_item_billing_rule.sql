-- PMS-956: say whether a contract item bills, instead of inferring it.
--
-- The recurring generator billed `item_type IN ('recurring_service', 'retainer')`
-- and nothing else read a contract item at all, so a `product` or `one_time`
-- row could be created, edited and read, and no invoice would ever carry it.
-- An MSP putting "setup fee, billed once" or "30 licences at 22.00 per user"
-- on a contract got no error and no warning; the row simply never became money.
--
-- The fix is a column that says what happens, not a type the generator has to
-- interpret. `item_type` describes WHAT the item is; `billing_rule` describes
-- what the generator does with it, and the two are different questions that
-- were being answered by one field.
--
-- Deliberately NOT `billing_frequency`, which already exists on this table with
-- a 'monthly' default and is read by no decision anywhere (only the DTO, the
-- INSERT, the UPDATE and the row mapping touch it). Giving that column meaning
-- is tempting and wrong here: its name promises per-item cadence, a quarterly
-- item on a monthly contract, which this change does not implement. Shipping
-- the name without the behaviour would replace one silent lie with a
-- better-looking one. It is left exactly as it is.

ALTER TABLE contract_items
    ADD COLUMN billing_rule VARCHAR(20) NOT NULL DEFAULT 'manual'
        CHECK (billing_rule IN ('every_period', 'once', 'manual'));

-- `once` needs per-item idempotency, which the period ledger cannot give:
-- `contract_invoice_runs` is UNIQUE on (tenant_id, contract_id, period_start),
-- so it records that a PERIOD was billed. A one-time item added in March would
-- bill again in April under a new period key. This is one fact living on the
-- thing it describes, claimed inside the generator's transaction with
-- `UPDATE ... WHERE billed_at IS NULL`, so no second ledger is introduced.
ALTER TABLE contract_items ADD COLUMN billed_at TIMESTAMPTZ;

-- The backfill preserves today's behaviour EXACTLY, and that is the point of
-- it. Every existing `product` and `one_time` row was written by somebody who
-- has not been charging for it; a backfill that started billing them, even
-- once, would send a client a charge for something recorded months ago that
-- nobody expected. So only the two types that bill today are marked as
-- billing, and everything else stays `manual` until an operator says otherwise.
UPDATE contract_items
SET billing_rule = 'every_period'
WHERE item_type IN ('recurring_service', 'retainer');

CREATE INDEX idx_contract_items_billing_rule
    ON contract_items (tenant_id, contract_id, billing_rule);
