//! `at+jwt` (RFC 9068) verification for legacy PSA endpoints.
//!
//! Lets the existing `AuthMiddleware` accept access tokens minted by
//! `mokosh-auth` alongside the legacy HS256 cookies during the
//! transition window. Verification is in-process: we hold a reference
//! to the same `OidcKeySet` that `mokosh-auth` already loaded, so there
//! is no JWKS fetch over the network.

use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use mokosh_auth::crypto::OidcKeySet;

use super::{CurrentUser, UserRole};

/// What we extract from a verified at+jwt. PSA code can use this directly
/// (id + tenant_id + role) or fetch the rest of the user record from
/// `mokosh_auth.users` if it needs email/names/timezone.
pub struct VerifiedAtJwt {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub role: UserRole,
    pub email: Option<String>,
}

/// Wraps the active key set + issuer URL. Cheap to clone (Arc).
#[derive(Clone)]
pub struct AtJwtVerifier {
    keys: Arc<OidcKeySet>,
    issuer: String,
    leeway_seconds: u64,
}

impl AtJwtVerifier {
    pub fn new(keys: Arc<OidcKeySet>, issuer: impl Into<String>) -> Self {
        Self {
            keys,
            issuer: issuer.into(),
            leeway_seconds: 30,
        }
    }

    /// Try to verify a Bearer token. Returns `None` for any token that
    /// is not a well-formed `at+jwt` we can validate; the caller should
    /// fall back to the legacy verifier in that case.
    pub fn try_verify(&self, token: &str) -> Option<VerifiedAtJwt> {
        let header = decode_header(token).ok()?;
        // RFC 9068: typ MUST be "at+jwt". Anything else is not our token.
        if header.typ.as_deref() != Some("at+jwt") {
            return None;
        }
        let kid = header.kid?;
        let dk = self.keys.decoding_key(&kid)?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.trim_end_matches('/')]);
        validation.leeway = self.leeway_seconds;
        // Audience is per-client; PSA endpoints don't gate on audience
        // here. Per-route audience checks can be added later by the
        // module that issues the resource.
        validation.validate_aud = false;

        let data = decode::<AtJwtClaims>(token, dk, &validation).ok()?;
        let claims = data.claims;

        let user_id = claims.sub.parse::<Uuid>().ok()?;
        let tenant_id = claims.mokosh_tenant_id.parse::<Uuid>().ok()?;
        let role = parse_mokosh_role(claims.mokosh_role.as_deref());

        Some(VerifiedAtJwt {
            user_id,
            tenant_id,
            role,
            email: None,
        })
    }
}

/// Build a `CurrentUser` from a verified at+jwt. Email / names / timezone
/// are empty: at+jwt deliberately omits PII. PSA handlers that need the
/// full record should query `mokosh_auth.users` by id.
pub fn current_user_from_at_jwt(v: &VerifiedAtJwt) -> CurrentUser {
    CurrentUser {
        id: v.user_id,
        tenant_id: v.tenant_id,
        email: v.email.clone().unwrap_or_default(),
        first_name: String::new(),
        last_name: String::new(),
        role: v.role,
        timezone: "UTC".to_string(),
        avatar_url: None,
        // No DB lookup here: at+jwt carries no profile-completion claim,
        // and this CurrentUser is only the lazy middleware-populated
        // view. The SPA gates onboarding off `/api/v1/auth/me`, which
        // hits the DB and returns the authoritative value. Default to
        // `true` so a stale propagation never traps a real user.
        profile_completed: true,
        date_format_string: None,
    }
}

#[derive(Debug, Deserialize)]
struct AtJwtClaims {
    sub: String,
    #[serde(default)]
    mokosh_tenant_id: String,
    /// Not present in the access token by default; included only if
    /// future scope additions populate it. Falls back to a low-privilege
    /// role so a missing claim cannot accidentally elevate.
    #[serde(default)]
    mokosh_role: Option<String>,
}

fn parse_mokosh_role(s: Option<&str>) -> UserRole {
    // mokosh-auth issues roles drawn from {admin, manager, finance,
    // member, readonly}. Map them into the legacy enum
    // {SuperAdmin, Admin, Manager, Technician, Dispatcher, Sales, Finance}.
    // Unknown values fall through to Technician (the default service
    // role) so a token without `mokosh_role` cannot quietly become an
    // admin.
    match s.unwrap_or("") {
        "super_admin" => UserRole::SuperAdmin,
        "admin" => UserRole::Admin,
        "manager" => UserRole::Manager,
        "finance" => UserRole::Finance,
        _ => UserRole::default(),
    }
}
