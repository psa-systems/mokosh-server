-- KB article rating: one vote per user account, mutually exclusive
-- (helpful XOR not_helpful), toggleable.
--
-- Before this table, kb_articles.helpful_count / not_helpful_count were
-- bare denormalized counters bumped by an UPDATE ... = + 1 with no
-- per-user record, so a single user could click thumbs-up/down
-- repeatedly and inflate both tallies. This table records one row per
-- (article, user) so the rating is one vote per account, mutually
-- exclusive between 'helpful' and 'not_helpful', and toggleable (voting
-- the same way twice removes the row, switching flips it).
--
-- The kb_articles counter columns are KEPT as denormalized caches so the
-- list/detail reads stay join-free. The service recomputes both counts
-- from this table on every vote (inside the same transaction) and writes
-- them back to kb_articles, so the cache can never drift from the source
-- of truth here.
--
-- No RLS: this table is created after the 024 triggers-and-RLS sweep,
-- matching every table added since (025-031, e.g. contract_invoice_runs).
-- Those tables enforce tenant isolation at the service layer (every
-- service method takes tenant_id explicitly and filters on it) rather
-- than via row-level security, per the repo's "No middleware-level
-- tenant scoping" convention. tenant_id is carried here so the votes
-- query can be tenant-scoped consistently with the rest of the module.

CREATE TABLE kb_article_votes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    article_id UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vote TEXT NOT NULL CHECK (vote IN ('helpful', 'not_helpful')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_kb_article_votes_article_user UNIQUE (article_id, user_id)
);

CREATE INDEX idx_kb_article_votes_article ON kb_article_votes(article_id);
CREATE INDEX idx_kb_article_votes_tenant ON kb_article_votes(tenant_id);
