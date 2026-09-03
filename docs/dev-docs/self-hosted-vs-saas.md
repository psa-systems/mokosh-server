# Self-hosted vs SaaS

Mokosh runs in two shapes, selected by `MOKOSH_DEPLOYMENT_MODE`
(`self-hosted` default, or `saas`). The difference is **who owns platform
identity**, and everything else here follows from that one fact.

| | `self-hosted` | `saas` |
|---|---|---|
| Platform credential | a `users` row's `password_hash`, owned here | a Bunyip identity; mokosh is only a Resource Server |
| `/auth/login` password branch | works | refused, *when SSO is mounted* (see below) |
| `/auth/forgot-password`, `/auth/reset-password` | work | refused, same condition |
| Account email (reset, welcome, new-login alert) | sent | not sent, same condition |
| Portal identity and portal email | unchanged | unchanged |
| Business notifications | unchanged | unchanged |

`self-hosted` is today's behaviour byte for byte. An unset value resolves to
it, and so does an unrecognised one *for mail dispatch*: falling back to `saas`
on a typo would silently stop a self-hosted deployment's password-reset mail,
which reaches the operator as a broken product with nothing in the log.
Falling back to `self-hosted` costs a SaaS instance a redundant email at worst.
An unrecognised value logs at `warn` there; an empty value is treated as unset,
because a forwarded-but-unset compose key arrives as `""` (PMS-836). Provider
selection reads the same variable and refuses an unrecognised value outright -
see [Default providers](#default-providers-pms-1011) below.

## Default providers (PMS-1011)

The mode is also the **hosting profile**: it supplies the default provider for
each capability, and the table is data in `src/utils/deployment.rs`
(`SELF_HOSTED_PROVIDER_DEFAULTS`, `SAAS_PROVIDER_DEFAULTS`), so a third mode
later is a data addition rather than a new `match` at every selection point.
There is no second deployment-shape variable.

| provider kind | `self-hosted` | `saas` |
|---|---|---|
| configuration | `environment` | `environment` |
| secrets | `database` | `database` |
| authentication | `local` | `bunyip`, then `local` |
| email | `log` | `log` |
| storage | `local` | `local` |

Nothing in the `self-hosted` column reaches outside the deployment, which is
what "the customer image boots and serves with no Bunyip, no Infisical and no
object store" means concretely;
`the_self_hosted_defaults_need_no_external_service` enforces it against
`EXTERNAL_SERVICE_PROVIDERS`.

Authentication is the one row that differs, and it is the row the mode exists
for: bunyip first, with the legacy local path still enabled behind it until
PMS-981 deprecates it, which is what a `saas` instance does today. The other
four rows match `self-hosted` deliberately. The `saas` profile has to reproduce
CURRENT deployed behaviour, and current deployed behaviour for secrets,
storage, email and configuration is whatever that deployment's own environment
sets. Writing `infisical` or `s3` into the table would be a guess about an
environment that is not in this repository, and not a merely inaccurate one: a
deployment that sets neither would change backend on the next restart, and
`InfisicalSecretStore::from_env` refuses to build without its own variables, so
the guess would present as a deployment that no longer boots. Moving those rows
needs the deployed values read first, which is PMS-1018.

**The profile supplies defaults and locks nothing.** Explicit configuration
wins for its own kind - `SECRET_BACKEND`, `STORAGE_BACKEND`, `SMTP_HOST`,
`OIDC_ISSUER` - and every provider stays available at runtime in both modes, so
an operator can enable a second one during a migration.

Each kind's resolution records **who decided it**, profile or explicit
(`EnablementSource`), and `main` logs one line per kind at boot. Every kind is
logged, not only the deviations: a provider left on by a default has to be
visible rather than assumed, which is the whole point of recording the source.

### The parse behaviour is split by consequence

Two readers of one variable, with two different failure modes:

- `DeploymentMode::parse` / `from_env` - warn and fall back to `self-hosted`.
  Used where the answer only gates behaviour with a safe default, which is mail
  dispatch, for the reason argued above.
- `DeploymentMode::parse_for_providers` / `from_env_for_providers` - refuse an
  unrecognised value and name the legal ones. Used where the answer chooses a
  provider. The fallback's reasoning does not carry here: the same typo would
  silently select a different set of providers, and a boot that ends with a
  message naming the legal values is far the cheaper failure. `main` reads it
  before the database is touched, so the failure names the mode rather than
  arriving from whichever provider happened to resolve first.

## The condition is a conjunction (PMS-905)

Local password auth closes when **both** are true:

1. `MOKOSH_DEPLOYMENT_MODE=saas`, and
2. the bunyip Resource-Server verifier is mounted - `OIDC_ISSUER` and
   `OIDC_AUDIENCE` are configured, so `create_api_router` received
   `Some(verifier)`.

The second half is the whole design. A `saas` deployment whose OIDC
configuration is missing or broken cannot authenticate anyone through SSO;
closing the local path behind it leaves **no way in at all**, and recovery means
editing environment variables and restarting. That is the PMS-289 shape: a
misconfigured IdP made fatal, which took staging and production down and needed
PMS-292 to restore service. So in that state the local path stays open and
`create_api_router` logs at `error`:

```
MOKOSH_DEPLOYMENT_MODE=saas but no Bunyip RS verifier is mounted
(OIDC_ISSUER / OIDC_AUDIENCE unset): local password login remains ENABLED
because it is the only auth path this instance has.
```

Loud, not fatal. The break-glass is narrower than it looks: a
bunyip-provisioned user has no `password_hash` at all
(`upsert_user_from_oidc` writes none) and is already refused by the credential
check in `login`, so the only accounts it admits are the bootstrap admin and
anything predating a switch to SaaS.

One predicate, `AuthService::local_password_auth_disabled`, answers this for
every site. `sends_local_account_email` is defined as its negation rather than
as its own test of the mode, so the endpoints and the mail can never disagree.
The state that would otherwise fall between them is `saas` with no verifier:
mail keyed on the mode alone would suppress the reset email there while login
stayed open, leaving a break-glass login nobody could recover a password for.

## What `saas` suppresses, and why (PMS-904)

Three emails exist only to service a local platform password. Each is worse
than silence when that password is not the credential, because each reads as
though it has solved the recipient's problem:

- **Password reset** - a link that sets a password opening nothing.
- **Welcome / set your password** - names a step that does not exist here.
- **New-login-location alert** - about a sign-in path Bunyip owns telling the
  user about, so a mokosh alert is a duplicate at best.

Each gate sits **above its token write**, not merely above the dispatch. The
suppressed mail is the only carrier of the `{user_id}.{secret}` those sites
mint - the plaintext lives in memory for the length of the call and nothing
else ever emits it - so writing one anyway leaves a live credential-bearing row
no recipient can redeem and nothing retires before its TTL.

### Deliberately not suppressed

The **login-approval code** (PMS-658). It is not a notification about an
account, it is one half of a challenge-response: `login` returns
`approval_required: true` with empty tokens and `verify_login_approval` demands
the emailed code. Suppressing the send would strand the caller mid-login with
nothing able to finish it - a lockout introduced by a mail change is worse than
the redundant email it saves. In practice it rarely arises: the gate is opt-in
via `LOGIN_APPROVAL_ENABLED` and only local password logins reach it, and those
are refused outright when SSO is mounted.

The **staff invitation** is also unchanged, and does not branch by mode.
`invitations/service.rs` has sent "Sign in to accept the invitation: {app_url}"
since PMS-244 made acceptance login-driven; there is no password-setup link to
drop, and that sentence is already correct in both modes, because in `saas`
signing in at that origin *is* the Bunyip flow.

## What `saas` refuses, and how (PMS-905)

Three entry points return **403** with one shared message naming single
sign-on, so a customer who tries the password box, then "forgot password", then
their old reset link is told the same thing three times rather than assembling
three guesses:

- `POST /auth/login`, password branch. Refused after the user lookup and the
  status check - so the answer does not depend on whether the address exists -
  and before the Argon2 verify, so no work is spent on a credential that cannot
  be accepted. Logged at `warn`: in a deployment that federates identity, this
  is somebody presenting a password at a door that is meant to be closed.
- `POST /auth/forgot-password`. Refused **before** the user lookup, and that
  ordering is load-bearing. This endpoint answers identically for a known and an
  unknown address so it never reveals whether an account exists; refusing after
  the lookup would give a known address a 403 while an unknown one kept the
  silent `200`, turning the fix into the account oracle the endpoint is written
  to avoid.
- `POST /auth/reset-password` (redemption). No new token is minted in this state,
  but one issued before the switchover stays valid for its 24h - or 7 days for a
  welcome link - and redeeming it would set a password that signs nobody in.
  Succeeding here would be the most convincing kind of dead end, because the
  customer would have just been told their password was changed.

### Untouched by the mode

- **The portal plane.** A portal identity is a `contacts` row with its own
  credential lifecycle (PMS-820), federated through Bunyip in neither mode, so
  `/portal/auth/*` and portal mail behave identically in both.
- **`/auth/refresh`.** It renews a session that already exists rather than
  minting one from a password, so it is not a local-credential entry point.
- **MFA enrolment** (`/auth/me/mfa/*`). It sits behind an authenticated session,
  which a bunyip-authenticated user has. A TOTP secret enrolled in `saas` is
  only ever checked by the local `login` path, so it does nothing there; that is
  a dead end worth revisiting, but it is not reachable by an unauthenticated
  caller and is out of PMS-905's scope.

## Mail transport

Independent of everything above, and not yet implemented: PMS-903 will read the
same flag to send through Bunyip's shared mailer API (BUNYIP-602) instead of
direct SMTP in `saas`, with `MailerConfig::build` selecting an `ApiMailer`.
Composition does not change; only the transport does. `DeploymentMode`
deliberately carries no transport knowledge, so that work lands on top of it
rather than revisiting it.
