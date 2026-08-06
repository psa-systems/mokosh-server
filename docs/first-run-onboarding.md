# First-run onboarding: the bootstrap admin (PMS-676)

How the very first administrator gets into a brand-new mokosh-server instance and configures it, including the case where email/SMTP is not yet set up.

## The chicken-and-egg this avoids

On a fresh instance email/SMTP is not configured, so no verification message can be sent. If admin access were gated on a verified email address, the first admin could never get in to configure email in the first place. mokosh-server does not have that gate: the production bootstrap-admin login does not depend on email verification, so first-run is unblocked by construction.

## Production: bootstrap admin via bunyip-as-OP

Production authenticates through bunyip-as-OP (the sole OP; see the "Auth" section of `CLAUDE.md`). The first admin signs in with bunyip, and bunyip's access token carries the platform-admin claim (`bunyip_role = "admin"`).

On that login mokosh runs `place_bunyip_user` (`src/modules/auth/middleware.rs`), which:

- Provisions the user's own tenant and JIT-creates the local shadow row (no pre-existing invite needed).
- Maps the `bunyip_role = "admin"` platform claim to mokosh `super_admin` via `effective_role_from_bunyip`.
- Returns an authenticated session regardless of `email_verified`. An unverified address only means no pending invite is consumed and the JIT row is stored against a placeholder address; it never blocks login or the super_admin grant.

So a fresh instance with no SMTP configured still lets the platform admin sign in with full super_admin rights.

### Steps

1. Spin up the instance (see `docs/quickstart.md` for the dev stack; production is the same server behind bunyip-as-OP with `OIDC_ISSUER` + `OIDC_AUDIENCE` set to bunyip).
2. Sign in through the SPA with the bunyip account that holds the platform-admin role. You land as `super_admin` with no email configured and no verification step.
3. Configure email as that admin: `PUT /api/v1/settings/email` (admin-only, `RequireAdmin`; PMS-638). The SMTP password is stored AES-256-GCM-encrypted and the live mailer is hot-swapped on write, so email starts working with no restart. Any field left unset falls back to the matching `SMTP_*` env var.
4. From here, invite the rest of the team. Later users go through normal verification: an invite to address X is only consumed by a bunyip login with a verified X (`place_bunyip_user`'s invite gate, PMS-248). Turning email on does not change or downgrade the bootstrap admin.

## Local development: the ADMIN_EMAIL / ADMIN_PASSWORD seed

For local dev without bunyip, `maybe_bootstrap_admin` (`src/modules/auth/bootstrap.rs`, called from `src/main.rs`) seeds a first admin at startup when BOTH `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set AND the `users` table is empty. That row is created already verified (`email_verified_at = NOW()`) with role `super_admin`, and legacy password login (`/api/v1/auth/login`) has no email-verification gate, so it too works with SMTP unconfigured.

This path is DEV ONLY (it is labelled as such in code and `.env.example`); it is ignored once any user exists. Production should use the bunyip path above, not this seed.

## What "no verification gate" means precisely

`email_verified` is read in three places, none of which block bootstrap-admin login:

- Invite consumption: a pending invite is honored only for a verified address (`place_bunyip_user`).
- Email persistence: the real address is stored on the JIT insert only when verified; otherwise a `<sub>@unresolved.invalid` placeholder is used (MAPPS-335). The placeholder is repaired on the first request after bunyip reports the address verified (`repair_placeholder_email`, PMS-635): the JIT insert runs once, so until then the row kept an address in the reserved `.invalid` TLD that every outbound email bounced off, and the invite gate above could never open for it.
- Google account-linking: linking Google to an existing unverified local account asks the user to sign in with a password first (`login_with_google`).

There is no `RequireVerified` extractor and no `email_verified_at`-based 403 anywhere in the request path.

## Tests

`tests/bunyip_login.rs`:

- `bootstrap_admin_unverified_email_still_gets_super_admin` - `email_verified = false` (SMTP unconfigured) plus the platform-admin claim still yields `super_admin` and an authenticated session.
- `bootstrap_admin_verified_email_still_gets_super_admin` - `email_verified = true` (SMTP configured) yields the same `super_admin`, proving enabling email does not downgrade the bootstrap admin.
