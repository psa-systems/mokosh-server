-- Dedicated schema for the auth subsystem. PSA tables stay in `public`.
-- Putting auth tables in their own schema makes future extraction to a
-- separate database trivial and simplifies grants / audit scope.

CREATE SCHEMA IF NOT EXISTS mokosh_auth;

-- Required extensions (uuid_generate_v4 is already loaded by the public
-- schema migrations; CITEXT we need ourselves for case-insensitive emails).
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS citext;

-- pgcrypto is not strictly required (we use uuid_generate_v4) but is
-- harmless and provides gen_random_bytes() if we ever need it server-side.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
