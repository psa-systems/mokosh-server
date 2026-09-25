-- KB articles: a parent link plus a company-filter index.
--
-- The per-client documentation shape needs an article to know it is
-- the client-specific version of a more generic one: one shared
-- "Onboarding" article, plus an Acme version and a Globex version that
-- hang off it. Migration 012 already reserved `related_article_ids` for
-- something similar, but nothing has ever read or written that column,
-- and its symmetric shape cannot express "this article is Acme's
-- version of that one" without a second column deciding direction. A
-- dedicated `parent_article_id` is the shape the read paths need.
--
-- `ON DELETE SET NULL` rather than `CASCADE`: the client-specific
-- procedures written under the generic article must survive if that
-- article is deleted. A future retention rule can walk from the
-- orphaned children and decide what to do with them, but a delete now
-- must not silently take them.
--
-- The GIN index on `company_ids` backs the new list filter's
-- `${n} = ANY(company_ids)` predicate. The staff-facing list adds a
-- company filter alongside the existing category / status / visibility
-- / text ones; without an index the predicate degrades to a sequential
-- scan of every article in the tenant.
--
-- No backfill: every existing row carries `parent_article_id = NULL`,
-- which is the "no parent, generic article" state. A separate follow-up
-- can classify the seeded articles once the SPA surfaces the link.

BEGIN;

ALTER TABLE kb_articles
    ADD COLUMN parent_article_id UUID REFERENCES kb_articles(id) ON DELETE SET NULL;

CREATE INDEX idx_kb_articles_parent ON kb_articles(parent_article_id);
CREATE INDEX idx_kb_articles_company_ids ON kb_articles USING gin (company_ids);

COMMENT ON COLUMN kb_articles.parent_article_id IS
    'The generic article this row is a client-specific version of. NULL for a top-level article. ON DELETE SET NULL so a deleted parent leaves the client-specific procedures written under it.';

COMMIT;
