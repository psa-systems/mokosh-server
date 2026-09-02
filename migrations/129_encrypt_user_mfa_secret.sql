-- PMS-871: widen `users.mfa_secret` so it can hold ciphertext instead of the
-- raw base32 TOTP shared secret.
--
-- 003_auth.sql declared the column `VARCHAR(100)`, which fit the 32-character
-- base32 secret with room to spare. The AES-256-GCM value written from
-- `src/modules/auth/mfa_secret.rs` is base64 of a 12-byte nonce plus the
-- ciphertext and its 16-byte GCM tag, 80 characters today; that still fits, but
-- the width is an accident of the plaintext it replaced and the next thing to
-- change (a longer secret, a different AEAD) would silently overflow it. TEXT
-- has no per-row cost in Postgres over a varchar of any width, so pinning a
-- length here buys nothing and can only fail a write.
--
-- No data change. Rows enrolled before this migration are still plaintext and
-- cannot be re-encrypted here, because a migration has no access to
-- `ENCRYPTION_KEY`. `AuthService` classifies a stored value on read and
-- rewrites a legacy plaintext one encrypted on the next successful
-- verification, so every enrolled user keeps working with no re-enrolment.

ALTER TABLE users
    ALTER COLUMN mfa_secret TYPE TEXT;
