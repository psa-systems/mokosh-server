-- PMS-730 groundwork: KB article as the PROCEDURE for working a ticket.
--
-- The MACD request flow needs the person working a ticket to have the
-- procedure attached: "this is a new-starter add, here is the article
-- describing how we perform one". That is a different relation from the
-- one migration 068 already added, and it deliberately does not reuse it.
--
-- 068 (`tickets.source_kb_article_id`, PMS-452) records the article a
-- ticket was opened FROM: the SPA's article surface offers "Open ticket
-- about this article", stamps that column, and
-- `KnowledgeBaseService::list_top_ticket_driving_articles` (PMS-485)
-- counts those stamps to answer "which articles drive the most tickets",
-- i.e. where the docs are FAILING the user. Stamping the same column
-- when we attach a procedure would fold every MACD request into that
-- count and invert its meaning: an article that successfully documents a
-- routine change would report as a documentation failure. The two links
-- point in opposite directions (article caused ticket vs ticket needs
-- article), so they get separate columns.
--
-- ON DELETE SET NULL mirrors 068: retiring an article leaves existing
-- tickets intact and only drops the linkage.
--
-- The partial index serves PMS-732's aggregation ("tracked time by
-- request type, surfaced on the article"), which reads every ticket
-- carrying a given procedure article. Partial so the overwhelming
-- majority of tickets, which have no procedure attached, stay out of it.
--
-- No RLS policy work here: `tickets` already carries the fail-closed
-- `tenant_isolation` policy, and a policy is attached per table, not per
-- column, so an added column inherits the existing coverage. (Contrast a
-- NEW table, which inherits nothing, because the DO-block loops in 024 /
-- 038 have already run - see 042_portal_setup_tokens.sql.)

ALTER TABLE tickets
    ADD COLUMN procedure_kb_article_id UUID REFERENCES kb_articles(id) ON DELETE SET NULL;

CREATE INDEX idx_tickets_procedure_kb_article
    ON tickets(tenant_id, procedure_kb_article_id)
    WHERE procedure_kb_article_id IS NOT NULL;
