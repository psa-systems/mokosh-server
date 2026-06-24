#!/bin/sh
# PMS-488: First-init provisioning for the Mokosh dev database. The postgres
# image runs every script in /docker-entrypoint-initdb.d/ exactly ONCE, when
# PGDATA is empty (a fresh volume), as the superuser over the trusted local
# socket and BEFORE the TCP listener opens. That ordering means the roles and
# extensions below always exist before mokosh-server connects via
# `postgres:5432`, with no race.
#
# Because this only runs against an empty data dir, the roles do not yet exist,
# so plain CREATE (no `|| true` / create-then-alter idempotency dance) is
# correct. To re-provision after changing a password in .env, wipe the volume
# with `just dev-clean` and start fresh - drift reconciliation is intentionally
# not handled here.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- PMS-285 RLS role split. mokosh_migrator (BYPASSRLS) runs migrations +
    -- bootstrap + cross-tenant workers; mokosh_app (NOBYPASSRLS) serves every
    -- request-scoped query, so a forgotten WHERE tenant_id fail-closes to zero
    -- rows instead of leaking across tenants.
    CREATE ROLE mokosh_migrator LOGIN BYPASSRLS PASSWORD '$MOKOSH_MIGRATOR_PASSWORD';
    CREATE ROLE mokosh_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '$MOKOSH_APP_PASSWORD';

    GRANT ALL ON SCHEMA public TO mokosh_migrator;
    GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO mokosh_app;
    GRANT USAGE ON SCHEMA public TO mokosh_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mokosh_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mokosh_app;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mokosh_app;

    -- Every table the migrator creates in later migrations auto-grants to
    -- mokosh_app, so the request-serving role can read/write new tables.
    ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mokosh_app;
    ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO mokosh_app;
    ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO mokosh_app;

    -- Untrusted extensions: only a superuser can CREATE them, so the
    -- unprivileged mokosh_migrator that runs the migrations cannot. Pre-create
    -- them here; every migration uses CREATE EXTENSION IF NOT EXISTS, so the
    -- migration step is then a no-op. public-schema migrations want uuid-ossp +
    -- pg_trgm; the mokosh-auth subsystem migrations also want citext + pgcrypto.
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
    CREATE EXTENSION IF NOT EXISTS citext;
    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    -- The mokosh-auth bootstrap (runs as mokosh_migrator) does
    -- CREATE SCHEMA mokosh_auth, which needs CREATE on the database; a plain
    -- BYPASSRLS role lacks it.
    GRANT CREATE ON DATABASE "$POSTGRES_DB" TO mokosh_migrator;
EOSQL

echo "[pg-init] mokosh_migrator / mokosh_app roles + extensions provisioned"
