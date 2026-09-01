# Auth / login / 2FA / session security audit (PMS-625)

One-time deep review of the mokosh-server authentication surface, requested in
PMS-625 ("Auth/login/2FA security audit ... before access expires ~Jul 7").
Scope per the issue: login flow, 2FA (TOTP + recovery codes), session/cookie
handling, and admin/entitlement (role) assignment.

- Reviewer / model: this pass was run with Claude Opus 4.8 (1M context). The
  issue names Claude Fable; that model was not available to the automated
  runner, so the strongest available model was used instead. The substitution
  is noted here rather than silently.
- Surface reviewed (line counts at review time): `src/modules/auth/service.rs`
  (2728), `middleware.rs` (983), `routes.rs` (641), `oidc_rs.rs` (574),
  `bunyip_webhook.rs` (292), `google_login.rs` (141), `rate_limit.rs` (77),
  plus `src/utils/totp.rs` (222), `src/utils/recovery.rs` (86), and the role
  model in `crates/mokosh-types/src/auth.rs`.
- Since this audit ran, PMS-837 deleted `google_login.rs` and the two
  `/api/v1/auth/google*` routes entirely (unconsumed surface). F2 below is
  therefore historical: the file it hardened no longer exists. Everything else
  in this report still refers to live code.

## Overall posture

The auth surface is heavily hardened by prior tickets (PMS-4, PMS-138,
PMS-256/258/260/261/285, PMS-502, PMS-503, MAPPS-334/335/337/348, PMS-591).
Positives confirmed during this pass:

- TOTP is RFC 6238 with a **constant-time** code compare and an RFC test
  vector; `verify` returns the matched step and the login path enforces
  **anti-replay** (`mfa_last_used_step`) plus a persistent, exponential-backoff
  **second-factor lockout** (PMS-502).
- Recovery codes carry 80 bits of entropy, are stored only as SHA-256 hashes,
  and are consumed atomically (`array_remove ... WHERE $1 = ANY(...)`).
- The Bunyip RS verifier pins `alg=EdDSA`, `iss`, `aud`, and `exp`, refuses
  HTTP redirects on JWKS/discovery fetches, and rate-limits JWKS force-refresh
  (MAPPS-337). No `alg:none` exposure.
- The `account_deleted` webhook verifies an HMAC-SHA256 over the **raw** body
  in constant time and **before** parsing, and is idempotent.
- `users` reads/writes are consistently tenant-scoped (`begin_with_tenant` +
  `WHERE tenant_id = $n`); cross-tenant lookups fail closed to `NotFound`.
- Password reset tokens are user-bound (`{user_id}.{secret}`), single-use, and
  reset invalidates all sessions.

## Findings

Severity is CVSS-flavored qualitative. "Fixed here" = addressed in the PMS-625
branch; `Tracked (KEY)` = carried by that YouTrack issue, which is where its
state lives. Every deferred finding below names its issue; read the state off
the issue, not off this table.

| # | Severity | Area | Finding | Disposition |
|---|----------|------|---------|-------------|
| F1 | High | Admin/role assignment | `PUT /api/v1/auth/users/{id}` (`update_user`) checked only `is_admin()`, not the PMS-503 `can_grant` ceiling. A tenant `admin` could set any user's role - including their own via `PUT /users/{self}` (not the role-sanitizing `/me`) - to `super_admin`, a platform-level cross-tenant account. Asymmetric with `create_user`, which already gates it. | **Fixed here** |
| F2 | High | OAuth callback | `google_login::callback_html` embeds `serde_json::to_string(payload)` into an inline `<script>`; the code comment claimed serde_json HTML-escapes `<>&` (it does not). The OAuth error branch reflects the fully attacker-controlled `error_description` query param into `payload.error`, so `GET /auth/google/callback?error=x&error_description=</script><script>...` is a reflected XSS on the API origin. A Google `given_name` reaches the success payload the same way. | **Fixed here** |
| F3 | Medium | Session revocation | As audited, the legacy HS256 access-token path in `auth_middleware` did not check `claims.sid` against `user_sessions` (only `refresh_token` did), so after a sign-out an outstanding **access** token still authenticated until it expired (up to 1h). Bounded by the 1h access TTL, and only ever affected the legacy path. MAPPS-531 put that `sid` check on the access path (`AuthService::session_is_live`, one indexed primary-key read per legacy request), which is what makes single-device sign-out immediate. PMS-880 takes the sign-out-everywhere half: it mounts `POST /api/v1/auth/logout-all` over `AuthService::logout_all`, which no route reached, and pins both halves with regression tests. Per-user stamping was considered and rejected, because the `sid` check already revokes every token of a user whose rows are all deleted. The password half of this is PMS-681's `iat`-vs-`password_changed_at` cutoff. | Tracked (PMS-880) |
| F4 | Medium | Password change | As audited, `change_password` updated the hash but did **not** revoke other sessions, unlike `reset_password` (which calls `logout_all`). A user changing their password because they suspect compromise left other sessions and refresh tokens live. Behavioral/UX decision (keep-current-session vs revoke-all). | Tracked (PMS-681) |
| F5 | Low | 2FA lockout | As audited, `login` returned `Unauthorized` for a failed **recovery code** without calling `register_failed_mfa`, so only failed TOTP codes armed the PMS-502 second-factor lockout. Recovery-code guessing was still bounded by the 5/min-per-email login limiter and 80-bit entropy, so brute force was infeasible, but the lockout coverage was asymmetric. | Tracked (PMS-694) |
| F6 | Low | Re-auth rate limiting | As audited, the password re-auth in `change_password` and `disable_mfa` was not rate-limited (the login limiter only guards `/login`). An attacker holding a stolen session could brute-force the current password to disable MFA / change the password without any per-account throttle. PMS-881 gives the two routes one shared failure-counted limiter (`ReauthRateLimiter`, 10/min per IP + 5/min per user id), checked before the credential comparison, so only a failed re-auth spends budget. | Tracked (PMS-881) |
| F7 | Info | Legacy JWT | `decode_token` deliberately does not yet pin `iss`/`aud` (mint side stamps them; strict flip deferred). Already tracked by **MAPPS-334**; no new issue - complete that ticket after the rolling refresh-TTL window rotates every live legacy token. | Tracked (MAPPS-334) |
| F8 | Info | Webhook replay | The `account_deleted` webhook has no timestamp/nonce window; a captured valid delivery can be replayed. Harmless today because the tombstone is idempotent, but any future non-idempotent event added to the same endpoint pattern would be exposed. | Tracked (PMS-882), which holds the "close this before the endpoint gains a non-idempotent event" precondition |

## Fixes applied on this branch

### F1 - role ceiling on the update path (`src/modules/auth/routes.rs`)

Added the same `can_grant` ceiling that `create_user` enforces:

```rust
if let Some(role) = request.role {
    if !user.role.can_grant(role) {
        return Err(AppError::Forbidden("Cannot assign a role above your own".to_string()));
    }
}
```

Regression test: `tests/auth.rs::update_user_enforces_role_ceiling` (admin ->
super_admin is 403; admin -> manager is 200).

### F2 - XSS-safe JSON embedding (`src/modules/auth/google_login.rs`)

`callback_html` now runs both the payload JSON and the origin JSON through
`escape_json_for_script`, which replaces `<`, `>`, `&`, U+2028, U+2029 with
their `\uXXXX` forms. These only occur inside JSON string literals, so the
escaped output is byte-for-byte equivalent JSON (proven by the round-trip test)
but can no longer close the `<script>` element. The misleading comment was
corrected. Unit tests:
`callback_html_neutralizes_script_breakout`,
`escape_json_for_script_is_reversible_json`.

## Where each deferred finding went

Every row that was not fixed on the PMS-625 branch has an owning issue. This
list is the index; the issues carry the detail and the state.

- F3 -> MAPPS-531 and PMS-880 (the sign-out half) and PMS-681 (the password-change half).
- F4 -> PMS-681, the same mechanism.
- F5 -> PMS-694.
- F6 -> PMS-881.
- F7 -> MAPPS-334.
- F8 -> PMS-882.

PMS-880, PMS-881 and PMS-882 were filed by PMS-857, which swept this document
for follow-up claims that named no issue.
