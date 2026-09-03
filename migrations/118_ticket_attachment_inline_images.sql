-- PMS-941: mark the attachments that are meant to be readable without a session.
--
-- An image embedded in a ticket description or note is fetched by the browser
-- as `<img src="...">`. An `<img>` carries no Authorization header and the SPA
-- holds a bearer rather than a cookie, so the URL that serves those bytes
-- cannot sit behind the auth middleware. PMS-923 made the same call for KB
-- article images.
--
-- Why a column rather than "serve any ticket attachment by id"
-- ------------------------------------------------------------
-- `ticket_attachments` has no MIME allowlist and a 25 MiB cap. It already holds
-- files nobody uploaded with a public URL in mind: portal uploads from a
-- customer, and every attachment on an inbound email that opened a ticket
-- (PMS-450). Serving that table by id alone would retroactively make an
-- invoice, a log bundle or a customer document fetchable by anyone holding a
-- UUID, under a contract those uploads were never made under.
--
-- So the public read serves ONLY rows flagged here, and only the inline-image
-- upload path sets the flag. Existing rows keep the authenticated-only contract
-- they were stored under, which is why the default is FALSE and this migration
-- backfills nothing.
ALTER TABLE ticket_attachments
    ADD COLUMN is_inline BOOLEAN NOT NULL DEFAULT FALSE;

-- The public read looks a row up by id and then checks the flag. Partial, so
-- the index covers only the rows that route can ever return.
CREATE INDEX idx_ticket_attachments_inline
    ON ticket_attachments (id)
    WHERE is_inline;

COMMENT ON COLUMN ticket_attachments.is_inline IS
    'PMS-941: set only by the inline-image upload path. The unauthenticated read at /api/v1/public/tickets/attachments/{id} serves these rows and no others.';
