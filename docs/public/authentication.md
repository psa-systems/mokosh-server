# Authentication

Mokosh authenticates callers through three parallel mechanisms, each with its own credential type, its own bearer shape, and its own gate. A caller lands in the one plane their credential decodes into; crossing between them is not possible.

## Bunyip OIDC (staff, the primary path)

Bunyip is the sole identity provider for staff users. A sign-in on the SPA is an OIDC authorization code flow against Bunyip, returning an access token the SPA presents to Mokosh as `Authorization: Bearer <token>`. The token carries the `at+jwt` type, signed by Bunyip, verified against Bunyip's JWKS.

Each incoming request runs the Bunyip verifier. If the token checks out, Mokosh looks up or provisions the matching local user row: a user signing in for the first time is given a personal tenant and shadow row (JIT provisioning). The matched user's role and tenant come from Mokosh's tables, never from a claim in the token.

A pending invite sent to an email address is consumed only when a Bunyip sign-in arrives with that address verified on the Bunyip side. An unverified address still signs in but does not consume an invite.

Operator configuration:

- `OIDC_ISSUER` and `OIDC_AUDIENCE` are required.
- `OIDC_BACKCHANNEL_CLIENT_ID` identifies this deployment to Bunyip's back-channel logout. Unset refuses every logout token.
- `BUNYIP_API_BASE_URL`, `BUNYIP_DIRECTORY_CLIENT_ID`, `BUNYIP_DIRECTORY_CLIENT_SECRET` turn on the directory lookup for grant invitations.
- `LOGIN_APPROVAL_ENABLED` turns on sign-in approval (see below).

## Legacy JWT (staff, migration path)

A deployment that predates the Bunyip move has a second staff path: HMAC-signed JWTs minted by `/api/v1/auth/login` against the local `user_sessions` table. A caller presenting a non-`at+jwt` bearer is decoded through this path. Both paths run the same per-tenant principal gate, so the handler never needs to know which path the caller used.

The legacy path accepts an optional TOTP code on login when the account has enrolled, and it is subject to the same login-approval hold.

The legacy path is a migration aid, not a target. New deployments should sign everyone in through Bunyip from day one and never use the legacy path.

## Contact plane

A customer-portal contact signs in on the portal with their email and password (and a TOTP code when enrolled). The login mints a contact bearer with its own `typ` claim and its own expiry. The bearer is scoped to the contact's company and reaches only the contact-plane routes under `/api/v1/contact/` plus the dual-plane routes that accept either bearer.

Contact credentials and resets:

- A contact sets their own password at first use. The MSP never sees it.
- An MSP admin can reset a contact's password by sending a reset mail.
- A contact can enroll two-factor from the portal, with the same TOTP shape staff uses and a recovery code set shown once.
- Password reset mail is a distinct audience from the staff reset mail. Both templates ship with the deployment.

The contact plane never crosses into the staff `users` table; a staff bearer never decodes on a contact-plane route and vice versa.

## API tokens

A user can mint a long-lived API token for machine access to the REST API. Tokens are prefixed `sfk_` and are shown once, immediately after creation. The server stores only a hash.

Tokens inherit the minting user's role, and the role clamps what the token can do. Revoking a token takes effect immediately on the next request.

Tokens carry no refresh: a token is valid until explicitly revoked or until its expiry (if the user set one). A token cannot be used to sign a user in to the SPA; it is for programmatic calls only.

## Two-factor

Two-factor is TOTP-based. A user enrolls through the SPA, scanning a QR code with an authenticator app, and the server stores the TOTP seed sealed under the `ENCRYPTION_KEY`. A recovery code set of 10 single-use codes is shown once at enrollment and never again.

Two-factor applies to the legacy staff login path and to the contact plane. The Bunyip path delegates to Bunyip for two-factor; what Bunyip accepts is what Mokosh sees.

An MSP admin can reset another staff user's two-factor from the user edit page. The reset is audited as `two_factor_reset`.

## Login approval

With `LOGIN_APPROVAL_ENABLED=true`, a sign-in from a country or device the account has not successfully signed in from before is held. The user receives a mail with a single-use approve link, and the sign-in completes only when they open it.

The device fingerprint is recorded on the first successful sign-in; a `user_devices` table is empty on a fresh deployment and populates lazily. An empty table means "baseline"; do not backfill. API sign-ins are exempt from the device trigger.

The approval hold is a security feature, and the mail must be deliverable. See [troubleshooting](troubleshooting.md) for the failure where the mail never arrives.

## What a token answers 403 on

- A route gated on `RequireAdmin` refuses every role below admin.
- A route gated on a feature toggle answers 404 (not 403) while the toggle is off, so the surface is invisible when disabled.
- A staff bearer on a contact-plane route and a contact bearer on a staff-only route both answer 403.
- A read-only role on a write method answers 403 at the middleware layer, before the handler runs.
- A caller whose role is not mirrored into the identity directory yet answers 403 for the brief window the mirror is catching up. This is rare and self-heals.

See [troubleshooting](troubleshooting.md) for how to tell a 403 from an infrastructure 403 upstream.
