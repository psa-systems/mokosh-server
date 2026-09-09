-- Roles the migrations grant to, created for a test cluster (PMS-988).
--
-- Migration 207 (`app_secrets`) ends with `GRANT ... TO mokosh_app`, and
-- Postgres rejects a GRANT to a role that does not exist (42704, `role
-- "mokosh_app" does not exist`). On a real deployment that is never reached:
-- `db::provision::provision_roles` creates the split roles at startup, BEFORE
-- `Database::new` and the migrations run (src/db/provision.rs), so by the time
-- migration 207 executes the role is there.
--
-- The Postgres-backed suite has no server startup. `#[sqlx::test]` connects to
-- a bare cluster as the superuser, creates a database per test and runs the
-- migrations itself, so nothing satisfies that precondition and every test in
-- the suite fails at migration 207 before its body runs. Whatever prepares the
-- test cluster therefore has to create the role, which is what this file is
-- for: `.forgejo/workflows/integration.yml` runs it against the job's postgres
-- service, and `just ensure-test-db-roles` runs it against the dev cluster.
--
-- Only the role NAME is reproduced here. The per-test databases are owned by
-- the superuser and no test connects as `mokosh_app` (tests/rls_serving_reads
-- .rs creates its own NOSUPERUSER NOBYPASSRLS role for the RLS checks), so the
-- LOGIN, password and privilege set `provision_roles` installs are deliberately
-- NOT copied: a second definition of a role that src/db/provision.rs owns is
-- exactly the kind of thing that drifts silently.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mokosh_app') THEN
        CREATE ROLE mokosh_app;
    END IF;
END $$;
