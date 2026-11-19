# Troubleshooting

Five concrete failures operators and admins actually hit, with the underlying cause and the fix.

## A signed-in user gets 403 on every API route

**Symptom**: the user signs in through Bunyip, the SPA loads, every API call returns 403 with `{"error":{"code":"forbidden"}}`.

**Cause**: one of:

- The Bunyip access token verification fails. The audience on the token does not match `OIDC_AUDIENCE`, or the issuer is not the configured `OIDC_ISSUER`. Mokosh rejects the token at the auth layer, and every route refuses the caller as unauthenticated (presenting as 403 on a route that would be admin-only, 401 on the open routes).
- The user's role is not mirrored into the identity directory yet. The Bunyip sign-in succeeded, the local user row exists, but a background mirror has not yet caught up. The gate refuses until it does.
- The user's bearer is a contact-plane bearer being presented on a staff-plane route. The server refuses to cross planes; a staff route refuses a contact bearer with 403.

**Fix**:

- Inspect the server log for the sign-in. A failed verification logs the reason (`audience mismatch`, `issuer mismatch`, `signature invalid`). Correct `OIDC_AUDIENCE` or `OIDC_ISSUER` in configuration and restart.
- For the mirror case, the condition self-heals within a minute. A persistent case points to the mirror worker being down; the server log names it.
- For the plane case, have the user sign out and back in to pick up the right bearer. If this keeps happening, the SPA is using the wrong token for the route; a client-side bug.

## A held login never releases

**Symptom**: `LOGIN_APPROVAL_ENABLED=true` is on. A user signs in from a new country or device, sees the "approval required" page, and never receives the approval mail.

**Cause**: SMTP is misconfigured. The sign-in is being held correctly; the mail cannot leave.

**Fix**:

- Check the server log. A failed SMTP send logs `warn` with the relay error (DNS, TLS, auth).
- Verify `SMTP_HOST`, `SMTP_PORT`, credentials and `SMTP_FROM`. Try sending a test mail: a simpler `openssl s_client` or `swaks` from inside the server container fails on the same thing without touching Mokosh.
- A deployment operator can reach `PUT /api/v1/settings/email` to update credentials without a restart; the live mailer swaps on write. See [first-run onboarding](operations/first-run-onboarding.md).
- While you fix SMTP, `MAIL_PROVIDER=log` (set on a hot-reload or with a restart) sends mail to the log at `info`, and the operator reads the approval link from the log and gives it to the user. This is a last resort, not a configuration.

Login approval is a security feature. If SMTP is truly down for an extended window, turn `LOGIN_APPROVAL_ENABLED=false` for the duration; every user stops being gated. Re-enable it once mail is back.

## Startup aborts with "migration N was previously applied but has been modified"

**Symptom**: the server fails to come up after an upgrade. The log reads `migration N was previously applied but has been modified`, with N a specific migration number.

**Cause**: the checksum of migration N in the new release does not match the checksum recorded in the database. One of three things:

- The database was restored from a version with a different migration history (uncommon but possible on cross-version restores).
- A prior release ran an edited version of the same migration locally (nobody should ever do this; the immutability rule is in place for this reason).
- Two different migrations collided on the same version number (caught by `just check-migration-versions` in CI; a database that got hit by it needs manual repair).

**Fix**:

- The migration is immutable on main. Do not edit it to clear the error.
- Identify N. Check out that migration in the committed source; note the checksum.
- Repair the `_sqlx_migrations` row for N with the committed checksum. This is a manual SQL edit; the operator has to decide the record is wrong and the committed source is right.
- Bring the server back up. It verifies the checksum again and accepts.

If the database was deliberately restored from a different version's dump, boot against the matching server version first and then upgrade. Each delta migration runs in turn and the checksums stay consistent.

## A Xero or QuickBooks sync reports "success" but the invoice does not appear

**Symptom**: an admin marks an invoice to be issued through Xero (or QuickBooks). The Mokosh side says it was sent to the provider. Logging into Xero (or QuickBooks) shows no invoice.

**Cause**: delegated issuing is asynchronous. "Sent to the provider" means "handed to the provider's intake endpoint", which is a queued attempt. The provider processes the intake asynchronously and webhooks back with the actual outcome. The webhook has not fired yet, or it fired and failed signature verification, or it fired and the operator does not see it because the webhook endpoint is not reachable from the provider.

**Fix**:

- Check `job_runs` for the delegation worker's recent runs. A failed submission logs the provider's error (401 from the provider is a token issue; 400 is often a mapping issue).
- Check the webhook endpoint from the provider's side. The provider's dashboard usually shows the last few delivery attempts and their response codes. A delivery that never reaches Mokosh at all points at a network or DNS issue; one that reaches it and returns 400 is a signature failure (`XERO_WEBHOOK_KEY` or `QUICKBOOKS_VERIFIER_TOKEN` mismatched).
- Check the per-company mapping. A Mokosh company with no Xero customer mapped refuses to submit the invoice; the error is visible in the failed `job_runs` row.

A confirmed submission on the provider side with no webhook is a provider-side configuration. A Mokosh-side failure almost always shows in `job_runs`.

## 500 from `/api/v1/auth/login/approval/...` after enabling login approval

**Symptom**: `LOGIN_APPROVAL_ENABLED` is flipped on. The first user to sign in gets a 500 on the approval poll, or the approval page errors out.

**Cause**: the `user_devices` table is empty. This is not a failure, it is baseline. The device trigger compares against a known-devices list; an empty list is the correct starting state, and the comparison code handles it. A 500 here means the server does not handle it, which has been a bug in past releases.

**Fix**:

- On a current release, this does not happen. If it does, you are on a release where the fix has not landed; upgrade.
- Do not backfill the `user_devices` table. The baseline is empty; every first successful sign-in writes its own row. Backfilling makes a brand-new deployment behave as if every user has signed in from every device, which defeats the purpose of the trigger.

## Where to go when none of these fit

- The `request_id` in the error response ties the client's complaint to the server log. Grep for it.
- Every background job writes to `job_runs`. A missing feature is often a worker that stopped.
- The provider status report (`GET /api/v1/providers/status` or the operator subcommand `mokosh-server provider-status`) names which provider each key is being served from; a change there is often the first visible sign of a configuration slip.
- `GET /api/v1/health` with a super-admin bearer returns the version, git hash and build date. Two servers reporting different builds under the same hostname is a reverse-proxy routing to an old container.
