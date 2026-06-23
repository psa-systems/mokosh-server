-- PMS-452 phase 1: KB article as ticket origin.
--
-- A `tickets.source_kb_article_id` FK lets a ticket record which KB
-- article inspired it. The SPA's KB-article surface gets an "Open
-- ticket about this article" affordance that pre-fills the ticket
-- form and stamps this column; downstream reporting can then ask
-- "which articles drive the most tickets" (i.e. where the docs are
-- failing the user).
--
-- ON DELETE SET NULL: if an admin retires the underlying article,
-- existing tickets stay intact; only the linkage drops. A future
-- "article history" follow-up could preserve the soft reference via
-- a `source_kb_article_slug` snapshot, but that is out of scope here.
--
-- Indexed on (tenant_id, source_kb_article_id) so the report "show
-- me every ticket opened from article X" is one index scan.

ALTER TABLE tickets
    ADD COLUMN source_kb_article_id UUID REFERENCES kb_articles(id) ON DELETE SET NULL;

CREATE INDEX idx_tickets_source_kb_article
    ON tickets(tenant_id, source_kb_article_id)
    WHERE source_kb_article_id IS NOT NULL;
