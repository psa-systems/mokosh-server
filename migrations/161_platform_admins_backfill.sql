-- MAPPS-513: backfill `platform_admins` from every existing
-- super-admin `users` row. Preserves `password_hash` so operators can
-- log in via `/platform/login` immediately with their current
-- super-admin credentials; from there they can `PUT /platform/me/password`
-- to set a credential distinct from the tenant identity plane.
--
-- `ON CONFLICT DO NOTHING` covers the edge case where two `users` rows
-- across different tenants share `role = 'super_admin'` and the same
-- email (would map to one platform admin row via the case-insensitive
-- email unique index).

INSERT INTO platform_admins (
    id, email, password_hash, first_name, last_name,
    timezone, locale, email_verified_at, last_login_at,
    mfa_enabled, mfa_secret, notification_preferences, settings,
    status, created_at, updated_at
)
SELECT DISTINCT ON (lower(email))
    id, email, password_hash, first_name, last_name,
    timezone, locale, email_verified_at, last_login_at,
    mfa_enabled, mfa_secret, notification_preferences, settings,
    CASE WHEN status = 'pending' THEN 'active' ELSE status END,
    created_at, updated_at
FROM users
WHERE role = 'super_admin'
ORDER BY lower(email), created_at ASC
ON CONFLICT DO NOTHING;
