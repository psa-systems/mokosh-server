//! Helpers shared across multiple handler modules.
//!
//! Each item here previously lived as a copy-pasted private fn/const in
//! two or more handler files; consolidating keeps a single source of
//! truth (PMS-199).

use mokosh_auth_core::{AuthError, UserRole};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::errors::HttpError;

/// Default scopes minted for first-party SPA logins (and tenant
/// switches) when the client omits an explicit `scope` field. `openid`
/// is required for an ID token; `email` populates the email/
/// email_verified ID-token claims; `offline_access` opts the SPA into
/// receiving a refresh token.
pub const DEFAULT_FIRST_PARTY_SCOPE: &[&str] = &["openid", "email", "offline_access"];

/// Minted token bundle returned to first-party SPAs by `/v1/auth/login`
/// and `/v1/auth/active-tenant`.
#[derive(Debug, Serialize)]
pub struct TokenBundle {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub id_token: String,
    pub refresh_token: String,
    pub scope: String,
}

/// Lightweight sanity check: one '@', no whitespace, dot in the domain.
/// The mailer rejects malformed addresses at send time as the
/// authoritative validation.
pub fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    let mut at = s.split('@');
    match (at.next(), at.next(), at.next()) {
        (Some(local), Some(domain), None) => {
            !local.is_empty()
                && !s.chars().any(char::is_whitespace)
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        _ => false,
    }
}

/// First 4 bytes of SHA-256(token), hex-encoded. Used as a non-reversible
/// correlation handle for log lines about opaque tokens.
pub fn token_hash_prefix(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let bytes = h.finalize();
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Admin-only guard. Returns `Forbidden` unless the role is `Admin`.
pub fn require_admin(role: UserRole) -> Result<(), HttpError> {
    if matches!(role, UserRole::Admin) {
        Ok(())
    } else {
        Err(HttpError(AuthError::Forbidden(
            "admin role required".into(),
        )))
    }
}
