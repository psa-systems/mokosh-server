-- PMS-188: guard against orphaning asset secrets written under the all-zeros
-- key.
--
-- Until this fix, AssetsService was constructed with `encryption_key =
-- [0u8; 32]` (src/modules/assets/service.rs `new()`), so every
-- credential_vault and configuration_item secret was encrypted under an
-- all-zeros key. This release wires the configured key in
-- (AssetsService::with_encryption_key at src/api/router.rs), which means any
-- pre-existing row can no longer be decrypted: its ciphertext is bound to the
-- zero key, the running service now holds the real key.
--
-- Resolved decision (mirrors migration 040's product-owner ruling, recorded in
-- dev-docs/rls-per-user-isolation.md): Mokosh is NOT in production and the
-- database is wiped before go-live, so no real zero-key secrets exist to
-- re-encrypt. The data re-encryption step is therefore intentionally skipped:
-- there is nothing to migrate. AES-256-GCM ciphertext is opaque to SQL (a
-- random nonce prefixes every blob), so a pure-SQL decrypt/re-encrypt is
-- impossible anyway; re-encryption, if ever needed, must run as a one-shot
-- Rust tool that reads with [0u8; 32] and writes with the configured key,
-- version-tagged, one tenant per transaction with a decrypt round-trip check.
--
-- What stays valuable is the guard: this migration asserts fail-loud that no
-- asset-secret rows are present at migrate time. On a fresh / wiped database
-- both tables are empty, so it is a no-op that passes by construction. If any
-- row IS present it was written under the zero key and would silently fail to
-- decrypt once the real key is live, so the migration RAISES instead of
-- leaving orphaned, undecryptable secrets in place. It performs no writes, so
-- it is idempotent and safe to re-run.

DO $$
DECLARE
    cred_rows bigint;
    config_rows bigint;
    msg text;
BEGIN
    SELECT count(*) INTO cred_rows FROM credential_vault;
    SELECT count(*) INTO config_rows FROM configuration_items;

    IF cred_rows > 0 OR config_rows > 0 THEN
        msg := format(
            'PMS-188 guard failed: asset secrets predate the configured '
            || 'encryption key (credential_vault: %s row(s), '
            || 'configuration_items: %s row(s)). These were encrypted under '
            || 'the all-zeros key and cannot be decrypted by the configured '
            || 'key. Re-encrypt them with a one-shot tool or wipe them before '
            || 'deploying this release.',
            cred_rows, config_rows
        );
        RAISE EXCEPTION '%', msg USING ERRCODE = 'check_violation';
    END IF;
END $$;
