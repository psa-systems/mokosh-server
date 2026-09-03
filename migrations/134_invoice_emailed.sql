-- PMS-992: what "sent" claims. An invoice moved to `sent` whether or not
-- anyone was emailed, so the record claimed a delivery that may never have
-- happened. The send now resolves its recipient first and mails inside the
-- transaction that freezes the invoice, and these two columns record the
-- outcome: who was emailed and when, or NULL for an invoice the operator
-- marked sent without emailing (`skip_email`), which is a hand-delivered
-- invoice and says so.
ALTER TABLE invoices
    ADD COLUMN emailed_at TIMESTAMPTZ,
    ADD COLUMN emailed_to VARCHAR(255);
