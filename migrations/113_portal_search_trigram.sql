-- Post-PMS-729 code-review finding #6: pg_trgm indexes for portal search.
--
-- portal_search runs one SELECT per (tickets, invoices, quotes, KB)
-- section on every keystroke; the finding folded the paired COUNT into
-- each SELECT via `COUNT(*) OVER ()`, cutting the round-trip count in
-- half. The remaining hazard is that `%q%` ILIKE with leading wildcards
-- forces a sequential scan on every column the search touches. On a
-- tenant with 100k+ tickets or 10k+ KB articles that pins a worker for
-- hundreds of ms per keystroke and puts real load on the plane.
--
-- Adding pg_trgm GIN indexes lets the planner use `col ILIKE
-- '%needle%'` as an index lookup. `tickets` already carries a trigram
-- index on `name` in the assets space; this migration adds coverage on
-- the four columns portal_search reads that lacked one:
--
--   tickets.ticket_number  (short strings, still worth indexing so an
--                           agent typing "T-1234" hits an index)
--   tickets.description    (long text; the big win)
--   invoices.invoice_number
--   invoices.po_number
--   quotes.summary
--   kb_articles.content    (long text; the biggest win)
--
-- `title` on tickets already has trgm coverage from migration 005; the
-- other titles are short and matched against the ILIKE pattern rarely
-- enough that adding indexes is not worth the write amplification. If
-- profiling later shows otherwise, another migration can add them.
--
-- `pg_trgm` is a first-party contrib extension; migration 012 (KB)
-- created the extension already so this file only adds indexes.

CREATE INDEX IF NOT EXISTS idx_tickets_ticket_number_trgm
    ON tickets USING gin (ticket_number gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_tickets_description_trgm
    ON tickets USING gin (description gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_invoices_invoice_number_trgm
    ON invoices USING gin (invoice_number gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_invoices_po_number_trgm
    ON invoices USING gin (po_number gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_quotes_summary_trgm
    ON quotes USING gin (summary gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_kb_articles_content_trgm
    ON kb_articles USING gin (content gin_trgm_ops);
