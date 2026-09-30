# Identity and auth invariants

Scope: The `users` / `identities` mirror, TOTP, `LOGIN_APPROVAL_ENABLED`, `ENCRYPTION_KEY` and `CORS_ORIGIN`.

Each section below is a convention moved verbatim from the repo `CLAUDE.md` (PMS-1437), which keeps a one-line index entry linking here. A new convention adds its full text here and one index line in [`CLAUDE.md`](../../CLAUDE.md).

## ENCRYPTION_KEY

`ENCRYPTION_KEY` must parse as 32 bytes (raw or 64 hex chars) via `utils::crypto::parse_encryption_key`. Used for AES-256-GCM at-rest encryption of per-tenant secrets (e.g. payment-gateway configs).

## CORS_ORIGIN

`CORS_ORIGIN` is comma-separated; required to be a valid header value or startup panics. Defaults to `[CLIENT_ORIGIN]`.

## Login approval (PMS-658)

`LOGIN_APPROVAL_ENABLED` (PMS-658) turns on the suspicious-login notify-and-approve gate; off by default because it can withhold a login, so it is opt-in per deployment for a staged rollout. When on and a password login clears password/MFA but comes from a new country (needs `IP2LOCATION_DB_PATH`) or a new device (client-supplied `device_id` in the login body), the session/tokens are withheld and a single-use 6-digit code is emailed; the client re-POSTs `/auth/login` with `approval_code` to finish (mirrors the `mfa_required` flow). Off = the PMS-657 alert-only behaviour. Gates password login in v1 (the portal path is a follow-up); tables `login_approvals` + `user_login_devices`.

## Identity mirror (PMS-1120)

The `users` <-> `identities` mirror runs ONE way (PMS-1120): `users` is where a human's profile is written and it flows to `identities`, never back. Two directions meant two lock orders - the forward trigger takes `users`, then `tenant_memberships`, then `identities`, while `sync_identity_to_users` took `identities` then `users` - so two transactions writing one person on opposite planes at the same instant deadlocked, and the loser's caller saw a 500 on an ordinary profile edit or sign-in. Migration 245 drops that trigger, which removes the cycle by construction rather than by every writer remembering a lock: an advisory lock taken inside a trigger only moves the cycle onto the advisory lock, because the row on its own plane is already held by the time either fires, and taking it in the application would be 24 call sites with one forgotten site enough to restore it. The direction that went was carrying almost nothing: `record_identity_mfa_success` stamps a watermark the mirror never carried (and so was rewriting thirteen columns on every seat at that email for nothing, which is what made the cycle easy to hit), `write_mfa_enabled` already wrote both planes itself because the trigger's RLS-filtered `UPDATE users` reached only the caller's tenant (PMS-1223), and `update_last_login` had the same unnoticed limit and now writes its own `users` row, with the forward mirror carrying the timestamp to the identity. A write that must reach both planes writes both, `users` FIRST; `auth::service::mirror_direction` fails `cargo test --lib` on an `UPDATE identities` that sets a mirrored column outside that shape, and `tests/identity_mirror_lock_order.rs` drives the interleaving that used to deadlock.

## TOTP secret (PMS-1055)

A TOTP secret has one representation on both planes, and no trigger carries it (PMS-1055): `users.mfa_secret` and `identities.mfa_secret` both hold the AES-256-GCM ciphertext PMS-871 defined, sealed once and written to both planes by the application in one transaction (`start_mfa_enrollment`, `upgrade_legacy_mfa_secret` and its identity-first twin, `disable_mfa`), and every reader on either plane goes through `mfa_secret::open`. Migration 195 took `mfa_secret` out of BOTH directions of the `users` <-> `identities` mirror, the way migration 164 took `password_hash` out for MAPPS-551, because a mirror that copies a secret verbatim can convert a sealed one back to plaintext: `record_identity_mfa_success` stamps `identities.mfa_last_totp_step` on every successful identity-plane verification, and while the reverse trigger carried the column that stamp - a write with nothing to do with the secret - rewrote the users-plane secret with whatever the identity plane held, silently and with nothing in a log. The INSERT branch of the forward trigger still copies it, for 164's reason: it seeds a brand-new identity row and so can overwrite nothing. `mfa_enabled` and the rest of the per-human profile columns still mirror normally; only the secret leaves. Before this, `identities.mfa_secret` was handed straight to `base32_decode`, so identity-first MFA login (a login body with no tenant hint) was a hard 500 for everyone enrolled after PMS-871, because base64 routinely carries `0`, `1`, `8`, `9`, `+` and `/` and the base32 alphabet is `A-Z2-7`.
