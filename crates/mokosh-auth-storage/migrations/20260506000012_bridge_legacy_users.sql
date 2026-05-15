-- One-shot bridge migration: copy legacy `public.users` rows into
-- `mokosh_auth.users` so SSO sign-in works for accounts created under
-- the legacy auth stack.
--
-- This migration is mokosh-server-specific: it references `public.users`,
-- a table that lives in the host application's schema. The
-- `IF EXISTS` guard makes it a no-op when the auth crates are reused
-- standalone (no PSA tables present), so the file does not need to be
-- removed if/when these crates ship as their own repo.
--
-- Idempotent via ON CONFLICT (id) DO NOTHING. Re-running picks up only
-- rows that have not already been bridged. The legacy table is NOT
-- dropped here: PSA modules still consume it during the transition
-- window. A follow-up migration will drop it once every PSA module has
-- been switched to read from `mokosh_auth.users`.
--
-- Column mapping:
--   id, tenant_id, password_hash, last_login_at, created_at,
--   updated_at, email_verified_at, locale, timezone, mfa_enrolled
--     -> preserved verbatim. Both stacks already use Argon2id PHC
--        strings (saas inheritance), so password hashes round-trip.
--   email -> CITEXT-cast for the case-insensitive unique index.
--   role  -> collapsed onto the new four-level set:
--       super_admin, admin     -> admin
--       manager                -> manager
--       finance                -> finance
--       technician, dispatcher,
--       sales                  -> member
--       anything else          -> readonly  (defensive)
--   status -> active -> active, pending -> pending,
--             inactive -> suspended, anything else -> pending.
--   first_name / last_name -> empty string is normalised to NULL so the
--                             new schema's optional columns reflect
--                             "not provided".

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'users'
    ) THEN
        INSERT INTO mokosh_auth.users (
            id,
            tenant_id,
            email,
            email_verified_at,
            password_hash,
            role,
            status,
            first_name,
            last_name,
            timezone,
            locale,
            mfa_enrolled,
            last_login_at,
            created_at,
            updated_at
        )
        SELECT
            u.id,
            u.tenant_id,
            u.email::CITEXT,
            u.email_verified_at,
            u.password_hash,
            CASE u.role
                WHEN 'super_admin' THEN 'admin'
                WHEN 'admin'       THEN 'admin'
                WHEN 'manager'     THEN 'manager'
                WHEN 'finance'     THEN 'finance'
                WHEN 'technician'  THEN 'member'
                WHEN 'dispatcher'  THEN 'member'
                WHEN 'sales'       THEN 'member'
                ELSE                    'readonly'
            END,
            CASE u.status
                WHEN 'active'   THEN 'active'
                WHEN 'pending'  THEN 'pending'
                WHEN 'inactive' THEN 'suspended'
                ELSE                 'pending'
            END,
            NULLIF(u.first_name, ''),
            NULLIF(u.last_name, ''),
            u.timezone,
            u.locale,
            u.mfa_enabled,
            u.last_login_at,
            u.created_at,
            u.updated_at
        FROM public.users u
        ON CONFLICT (id) DO NOTHING;
    END IF;
END $$;
