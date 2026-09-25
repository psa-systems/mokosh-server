-- Record on the table what the codebase's stance on credential secrets
-- is, so the next reader does not have to reconstruct the answer from
-- the presence or absence of an external-vault integration.
--
-- Mokosh stores credential secrets locally in `credential_vault`,
-- encrypted at rest under the same `ENCRYPTION_KEY` that protects every
-- other secret column, and every read of a plaintext value flows
-- through the audited reveal endpoint at
-- `POST /api/v1/assets/{asset_id}/credentials/{id}/reveal`. That handler
-- writes an `asset_audit_log` row so an operator can see who read what
-- and when. The alternative was to reference an external vault; that
-- would put per-client credentials in a system the technician does not
-- already have open while working a ticket, which is the reverse of
-- what the per-client-documentation surface is here to fix.
--
-- This COMMENT stops a future reader from concluding the vault is a
-- placeholder just because there is no `EXTERNAL_VAULT_URL`. Amending
-- code comments is a follow-up; the table comment is where the stance
-- has to live because migrations are the append-only ledger.

COMMENT ON TABLE credential_vault IS
    'Locally stored credential secrets. Each row is a company- and asset-scoped credential (`local_admin` / `domain` / `ssh` / `api` / `other`), with username / password / notes encrypted under `ENCRYPTION_KEY`. Reveal is a dedicated endpoint that audits every read to `asset_audit_log`. Mokosh deliberately stores credential secrets here rather than referencing an external vault; the reveal audit trail is the control that made that acceptable.';
