//! Build the auth router. Mount under whatever prefix the host
//! application chooses (typically `/`).

use axum::http::{header, Method};
use axum::routing::{get, post};
use axum::Router;
use futures_util::future::BoxFuture;
use mokosh_auth_core::{
    AuthError, InviteRepository, MembershipRepository, MfaChallengeRepository,
    PasswordResetTokenRepository, RecoveryCodeRepository, SignupTokenRepository, TenantId,
    TotpRepository,
};
use mokosh_auth_crypto::EncryptionKeySet;
use mokosh_auth_oidc::OidcProvider;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use url::Url;

use crate::cookies::CookieConfig;
use crate::email::Mailer;
use crate::handlers::{
    auth as auth_h, discovery as disc_h, invites as invites_h, mfa as mfa_h, oidc as oidc_h,
    password_reset as pwd_reset_h, sessions as sessions_h, signup as signup_h,
    tenants as tenants_h, users as users_h,
};
use crate::local_auth::LocalAuth;
use crate::rate_limit::RateLimiter;

/// Resolve a tenant's display name. Owned by the host app
/// (mokosh-server reads `public.tenants`); the auth-http crate stays
/// schema-agnostic by accepting a closure. Returns `None` for unknown
/// tenant ids; callers fall back to a generic "Mokosh" label.
pub type TenantNameLookup =
    Arc<dyn Fn(TenantId) -> BoxFuture<'static, Option<String>> + Send + Sync>;

/// Resolve a tenant's display name AND kind ("personal" | "org").
/// Used by /v1/auth/memberships to render the switcher with
/// appropriate badges. Same isolation reason as TenantNameLookup.
pub type TenantInfoLookup =
    Arc<dyn Fn(TenantId) -> BoxFuture<'static, Option<(String, String)>> + Send + Sync>;

/// Create a brand-new personal tenant for a self-signing-up user.
/// Inserts a row in `public.tenants` (kind='personal', name derived
/// from the email) and returns its id. Owned by the host app for the
/// same schema-isolation reason as TenantNameLookup. Failures bubble
/// up as `AuthError::Storage`.
pub type PersonalTenantCreator = Arc<
    dyn Fn(String /* email */) -> BoxFuture<'static, Result<TenantId, AuthError>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct AuthHttpState {
    pub provider: OidcProvider,
    pub local_auth: Arc<LocalAuth>,
    pub cookie_cfg: CookieConfig,
    /// URL of the OP login UI that `authorize` redirects to when the
    /// user is not authenticated. Hosted by the front-end (mokosh-clients).
    pub login_url: Url,
    /// In-memory rate limiter for login + token endpoints. Shared
    /// across the request handlers via `Arc`. Phase-1: per-replica.
    pub rate_limiter: Arc<RateLimiter>,
    /// Admin-invite repository (Phase 1 of registration system).
    pub invites: Arc<dyn InviteRepository>,
    /// (user, tenant) memberships. Sourced of truth for tenant access;
    /// the existing `mokosh_auth.users.tenant_id` is becoming a "home
    /// tenant" pointer as the membership model takes over. Phase 1
    /// just wires the repo; subsequent phases (self-signup,
    /// membership-aware invite-accept, tenant switcher) consume it.
    pub memberships: Arc<dyn MembershipRepository>,
    /// Self-signup tokens. Issued by /v1/auth/signup, consumed by
    /// /v1/auth/signup/by-token/{token}/complete. Phase 2 of doc 10.
    pub signup_tokens: Arc<dyn SignupTokenRepository>,
    /// Password-reset tokens. See docs/mokosh-smtp/05-password-reset.md.
    pub password_reset_tokens: Arc<dyn PasswordResetTokenRepository>,
    /// Whether public self-signup is enabled. PSA hub deployments
    /// keep this false (registration is admin-invite-gated); the
    /// a8n / individual SKU sets it true. Set via the
    /// `MOKOSH_PUBLIC_SIGNUP_ENABLED` env var at bootstrap.
    pub public_signup_enabled: bool,
    /// Host-app closure that creates a new personal tenant in
    /// `public.tenants`. The auth crate does not own that table,
    /// so the call goes through this closure.
    pub create_personal_tenant: PersonalTenantCreator,
    /// Outbound email for invites (and future password reset / magic
    /// link). Stub `LogMailer` in dev; `LettreMailer` in prod.
    pub mailer: Arc<dyn Mailer>,
    /// Public URL the SPA serves the invite-accept page on (e.g.
    /// `https://${USER}-mokosh.a8n.run`). Combined with the raw token
    /// to build the shareable invite link returned in the issue +
    /// resend responses, so admins can copy the link directly out of
    /// the UI without depending on email delivery.
    pub accept_base_url: String,
    /// Tenant-name resolver. The auth crates do not own the tenants
    /// table, so the host app injects this closure.
    pub tenant_name: TenantNameLookup,
    /// Tenant info resolver: name + kind. Used by the memberships
    /// endpoint and the SPA tenant switcher; injected for the same
    /// schema-isolation reason as `tenant_name`.
    pub tenant_info: TenantInfoLookup,
    // --- MFA ---
    pub totp: Arc<dyn TotpRepository>,
    pub recovery_codes: Arc<dyn RecoveryCodeRepository>,
    pub mfa_challenges: Arc<dyn MfaChallengeRepository>,
    /// AES-256-GCM key set for at-rest encryption of TOTP shared secrets.
    /// Built at bootstrap from `AuthConfig::data_encryption_key` (plus the
    /// optional previous key for rotation).
    pub dek: Arc<EncryptionKeySet>,
    /// Active DEK version. New TOTP enrollments use this; rotation is
    /// "bump this number, leave the old key as `prev`, re-encrypt at
    /// leisure."
    pub dek_version: u16,
    /// Issuer label shown in authenticator apps. Today the host app
    /// passes "Mokosh" or the deployment-specific brand.
    pub mfa_issuer: String,
}

pub fn build_router(state: Arc<AuthHttpState>) -> Router {
    // Permissive CORS on the OIDC surface. These endpoints are
    // designed to be called cross-origin by browser SPAs:
    //   - /.well-known/openid-configuration and jwks.json are public
    //     metadata
    //   - /oauth2/token, /userinfo, /revoke take Authorization headers
    //     and PKCE proofs, never cookies (cross-origin cookie use
    //     would defeat the SPA model anyway)
    // We deliberately do NOT enable allow_credentials, since the OIDC
    // flow uses Bearer tokens. /oauth2/authorize and /oauth2/logout
    // are reached via top-level browser navigation (set_href), not
    // fetch, so they do not need CORS at all but allowing them is
    // harmless. /login is same-origin only.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);

    Router::new()
        // Discovery
        .route(
            "/.well-known/openid-configuration",
            get(disc_h::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(disc_h::jwks))
        // OIDC
        .route("/oauth2/authorize", get(oidc_h::authorize))
        .route("/oauth2/token", post(oidc_h::token))
        .route("/oauth2/userinfo", get(oidc_h::userinfo))
        .route("/oauth2/revoke", post(oidc_h::revoke))
        .route("/oauth2/logout", get(oidc_h::logout))
        // Local password authentication. The SPA posts here directly and
        // (when supplying `client_id`) gets back a token bundle, so users
        // never see a separate OP-hosted login form. The OIDC authorize
        // endpoint above is kept available for future relying parties; if
        // they hit it without an OP session we currently 404 the
        // login-redirect path - that gets wired to a real RP login screen
        // when the first external RP is onboarded.
        .route("/v1/auth/login", post(auth_h::login))
        .route("/v1/auth/logout", post(auth_h::logout))
        // Admin invites (admin-gated)
        .route(
            "/v1/auth/invites",
            post(invites_h::issue).get(invites_h::list_open),
        )
        .route("/v1/auth/invites/{invite_id}/revoke", post(invites_h::revoke))
        .route("/v1/auth/invites/{invite_id}/resend", post(invites_h::resend))
        // Public token-gated invite endpoints
        .route(
            "/v1/auth/invites/by-token/{token}",
            get(invites_h::read_by_token),
        )
        .route(
            "/v1/auth/invites/by-token/{token}/accept",
            post(invites_h::accept_by_token),
        )
        // Self-service session management. Bearer-authed, cross-origin
        // friendly (no cookie required).
        .route("/v1/auth/sessions", get(sessions_h::list_my_sessions))
        .route(
            "/v1/auth/sessions/{session_id}/revoke",
            post(sessions_h::revoke_my_session),
        )
        // Admin user management.
        .route("/v1/auth/users", get(users_h::list_users))
        .route(
            "/v1/auth/users/{user_id}/suspend",
            post(users_h::suspend_user),
        )
        .route(
            "/v1/auth/users/{user_id}/reactivate",
            post(users_h::reactivate_user),
        )
        // Self-signup. Public, rate-limited. Only enabled when
        // MOKOSH_PUBLIC_SIGNUP_ENABLED=true at bootstrap; otherwise
        // every endpoint here returns 404 signup_disabled.
        .route("/v1/auth/signup", post(signup_h::start))
        .route(
            "/v1/auth/signup/by-token/{token}",
            get(signup_h::preview),
        )
        .route(
            "/v1/auth/signup/by-token/{token}/complete",
            post(signup_h::complete),
        )
        // Password reset. Public, rate-limited per docs/mokosh-smtp/05.
        .route("/v1/auth/password-reset", post(pwd_reset_h::start))
        .route(
            "/v1/auth/password-reset/by-token/{token}",
            get(pwd_reset_h::preview),
        )
        .route(
            "/v1/auth/password-reset/by-token/{token}/complete",
            post(pwd_reset_h::complete),
        )
        // MFA enrollment (Bearer-authed; user enrolls themselves).
        .route("/v1/auth/mfa/setup", post(mfa_h::setup))
        .route("/v1/auth/mfa/confirm", post(mfa_h::confirm))
        // MFA verify: consumes the login challenge issued by /v1/auth/login
        // when the account has MFA on; no Bearer (the challenge is the auth).
        .route("/v1/auth/mfa/verify", post(mfa_h::verify))
        // Step-up gate for destructive MFA operations.
        .route("/v1/auth/mfa/step-up/start", post(mfa_h::step_up_start))
        .route("/v1/auth/mfa/step-up/verify", post(mfa_h::step_up_verify))
        // Recovery codes: list/regenerate (regenerate is step-up-gated).
        .route("/v1/auth/mfa/recovery-codes/regenerate", post(mfa_h::regenerate_recovery_codes))
        .route("/v1/auth/mfa/status", axum::routing::get(mfa_h::status))
        // Disenroll (self) - step-up-gated; admin force-disenroll is
        // mounted under /v1/auth/users to keep the URL space tidy.
        .route("/v1/auth/mfa/disable", post(mfa_h::disable))
        .route(
            "/v1/auth/users/{user_id}/mfa/disenroll",
            post(mfa_h::admin_force_disenroll),
        )
        // Membership-aware tenant switcher. Bearer-authed.
        .route("/v1/auth/memberships", get(tenants_h::list_my_memberships))
        .route(
            "/v1/auth/active-tenant",
            post(tenants_h::switch_active_tenant),
        )
        .layer(cors)
        .with_state(state)
}
