-- PMS-681: record the wall-clock time of a user's last password change so an
-- access token minted before it can be rejected immediately, closing the
-- up-to-1h window where a stateless access token outlived a password reset.
--
-- `reset_password` and `change_password` stamp this to NOW(); the auth
-- middleware rejects any access token whose `iat` is earlier. NULL means the
-- password has not changed since this column was added, which imposes no
-- cutoff, so tokens already in flight keep working across the deploy.
ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMPTZ;
