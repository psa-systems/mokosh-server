-- PMS-1244: verify one token hash per redemption, not one per row.
--
-- `password_reset_tokens.token_hash` and `portal_setup_tokens.token_hash` are
-- salted Argon2 hashes, which cannot be equality-matched: `idx_portal_setup_
-- token ON portal_setup_tokens(token_hash)` (042) has never served a lookup
-- and is dead. Every redemption instead scanned every non-expired candidate
-- row for the bound user/contact and ran an Argon2 verify against each one in
-- a loop, which is an unrate-limited O(N) Argon2-verify DoS amplifier.
--
-- `lookup_hash` is a SHA-256 hex digest of the same secret the emailed token
-- carries (`utils::crypto::sha256_hex`), stored alongside `token_hash` and
-- equality-matchable, so a redemption looks the row up directly and runs
-- exactly one Argon2 verify against it. SHA-256 is fast and gives no offline
-- protection by itself; the secret is 64 characters of `generate_token`
-- output (about 380 bits of entropy from an alphanumeric alphabet), so a
-- brute force against the lookup column is infeasible, and the actual
-- credential check stays the slow Argon2 compare against the matched row.
--
-- Nullable and unbackfilled: an existing pending token's row has no `secret`
-- left in the database to derive it from (only the Argon2 hash was ever
-- stored), so a row minted before this migration keeps `lookup_hash NULL`
-- and simply cannot be looked up by it; it ages out at its own `expires_at`
-- same as before. Every row minted from here on gets one.

ALTER TABLE password_reset_tokens ADD COLUMN lookup_hash VARCHAR(64);
ALTER TABLE portal_setup_tokens ADD COLUMN lookup_hash VARCHAR(64);

CREATE INDEX idx_password_reset_token_lookup_hash
    ON password_reset_tokens(user_id, lookup_hash);

-- Repurposes the dead `idx_portal_setup_token(token_hash)` index: same slot
-- in the naming scheme, now over the column that can actually be
-- equality-matched.
DROP INDEX idx_portal_setup_token;
CREATE INDEX idx_portal_setup_token_lookup_hash
    ON portal_setup_tokens(contact_id, lookup_hash);
