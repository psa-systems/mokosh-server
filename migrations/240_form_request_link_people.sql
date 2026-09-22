-- PMS-737: one client request covering several people.
--
-- A request for five starters is five units of work: the SLA clock, the time
-- entries, the billing and the technician's checklist are all per ticket, and
-- five people on one ticket makes the PMS-732 measured duration meaningless.
-- So the PSA-native shape is a PARENT ticket with a child per person, through
-- the `tickets.parent_ticket_id` this schema has carried since migration 005.
--
-- What the parent carries is the decision this records: NOTHING but the
-- request. No SLA, no assignee, no time. Every child gets its own, so the
-- per-person average stays an average over people. A parent with no time
-- drops out of the PMS-732 report by itself, because that report counts only
-- tickets with time entries.
--
-- The link, not the form definition, is what becomes multi-person: the form
-- model stays flat (PMS-731 rejected repeat groups), and the MSP says how many
-- people a link is for when issuing it.

ALTER TABLE form_request_tokens
    -- How many submissions this link was issued for. 1 is today's behaviour,
    -- and the default, so every existing link and every link issued without
    -- asking for more stays single-use.
    ADD COLUMN uses_allowed INTEGER NOT NULL DEFAULT 1
        CHECK (uses_allowed BETWEEN 1 AND 50),
    -- How many are left. Decremented on each redemption; at zero the link
    -- answers exactly as a spent single-use link does.
    ADD COLUMN uses_remaining INTEGER NOT NULL DEFAULT 1
        CHECK (uses_remaining >= 0),
    -- The parent ticket a multi-person link files its children under. NULL for
    -- a single-person link, which stays one ticket and no parent. SET NULL
    -- rather than CASCADE: losing the parent must not delete the record of the
    -- link that was issued.
    ADD COLUMN parent_ticket_id UUID REFERENCES tickets(id) ON DELETE SET NULL;

-- A link already redeemed has nothing left; one still live has its single use.
-- `used_at` keeps its meaning for both: stamped when the LAST use is spent.
UPDATE form_request_tokens
SET uses_remaining = CASE WHEN used_at IS NULL THEN 1 ELSE 0 END;

-- Which submission a link produced is no longer one row. `submission_id` holds
-- the FIRST, for the existing one-to-one reads; this is the whole set, and it
-- is what the parent's children are counted from.
ALTER TABLE form_submissions
    ADD COLUMN request_token_id UUID REFERENCES form_request_tokens(id) ON DELETE SET NULL;

CREATE INDEX idx_form_submissions_request_token
    ON form_submissions(request_token_id)
    WHERE request_token_id IS NOT NULL;

UPDATE form_submissions s
SET request_token_id = t.id
FROM form_request_tokens t
WHERE t.submission_id = s.id AND t.tenant_id = s.tenant_id;
