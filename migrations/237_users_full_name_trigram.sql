-- PMS-1247: the ticket-list search ORs a `(first_name || ' ' || last_name) ILIKE`
-- branch against `users`. It was the one branch of that predicate with no
-- trigram index, which stops Postgres building a BitmapOr across the OR.
-- The expression matches `text_match` in src/modules/tickets/service.rs exactly.
CREATE INDEX IF NOT EXISTS idx_users_full_name_trgm
    ON users USING gin ((first_name || ' ' || last_name) gin_trgm_ops);
