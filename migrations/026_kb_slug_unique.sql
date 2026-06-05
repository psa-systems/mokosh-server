-- PMS-79: enforce per-tenant unique slugs for KB categories and articles.
--
-- The KB service (src/modules/knowledge_base/service.rs) checks slug
-- uniqueness at the application layer before INSERT and returns 409
-- Conflict on a duplicate within the tenant. These constraints are the
-- database backstop for the same invariant so a concurrent insert that
-- races the app-layer check still fails closed (the existing
-- `From<sqlx::Error>` maps SQLSTATE 23505 to AppError::Conflict).
--
-- Migration 012 created non-unique helper indexes on (tenant_id, slug)
-- for lookups; a UNIQUE constraint creates its own backing index that
-- serves the same point lookups, so the old indexes are dropped to avoid
-- maintaining two indexes over identical columns. The seed data
-- (migration 023) inserts only distinct category slugs within the
-- default tenant and no articles, so no existing row violates these.

DROP INDEX IF EXISTS idx_kb_categories_slug;
DROP INDEX IF EXISTS idx_kb_articles_slug;

ALTER TABLE kb_categories
    ADD CONSTRAINT uq_kb_categories_tenant_slug UNIQUE (tenant_id, slug);

ALTER TABLE kb_articles
    ADD CONSTRAINT uq_kb_articles_tenant_slug UNIQUE (tenant_id, slug);
