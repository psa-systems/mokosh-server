-- Prevent duplicate (user_id, user_agent) op_sessions rows on concurrent
-- first-login.
--
-- The resume-or-create path previously guarded itself with
-- `SELECT ... FOR UPDATE`, but under READ COMMITTED that lock protects
-- nothing when no row exists yet: two concurrent first-logins both see
-- "no existing row" and both take the INSERT branch, producing two rows
-- for the same (user, user_agent). Enforce uniqueness at the database
-- level so the application can collapse the path to an atomic upsert.

-- Collapse any pre-existing duplicates first, keeping the most
-- recently-active row in each (user_id, user_agent) group so the unique
-- index can be built. `IS NOT DISTINCT FROM` groups NULL user_agents
-- (e.g. CLI logins) together, matching the application's lookup.
DELETE FROM mokosh_auth.op_sessions a
USING mokosh_auth.op_sessions b
WHERE a.user_id = b.user_id
  AND a.user_agent IS NOT DISTINCT FROM b.user_agent
  AND (a.last_active_at, a.id) < (b.last_active_at, b.id);

-- NULLS NOT DISTINCT (PostgreSQL 15+) so unknown user_agents (NULL) also
-- collapse to a single row, mirroring the `IS NOT DISTINCT FROM`
-- semantics the application uses and enabling ON CONFLICT inference on a
-- nullable column.
CREATE UNIQUE INDEX op_sessions_user_agent_uq
    ON mokosh_auth.op_sessions (user_id, user_agent) NULLS NOT DISTINCT;
