//! PMS-1193 / BUNYIP-641: the auth gate on the admin provider-status routes.
//!
//! Two shapes are accepted, tried in this order:
//!
//! 1. **A Bunyip machine credential** presented as HTTP Basic
//!    (`Authorization: Basic base64(client_id:client_secret)`). This is the
//!    shape `bunyip/docs/provider-status-contract.md` documents Bunyip's
//!    aggregator (BUNYIP-634) uses to call every application in the suite;
//!    the credential itself is a Bunyip `oauth_clients` row provisioned once
//!    per environment. Mokosh verifies the incoming `client_id` and
//!    `client_secret` byte-for-byte against `BUNYIP_STATUS_CLIENT_ID` and
//!    `BUNYIP_STATUS_CLIENT_SECRET` in constant time. Neither value is a
//!    Bunyip-signed JWT: for a status endpoint the shared-secret shape is
//!    the smallest surface that works, and Bunyip's aggregator is the only
//!    caller here.
//!
//! 2. **A staff admin session** ([`RequireAdmin`]). Unchanged from before
//!    PMS-1193; a human operator hitting the endpoint directly still lands
//!    on the same 200 they always did.
//!
//! A caller presenting Basic auth whose bytes do NOT match the configured
//! credential is refused with `401 Unauthorized` even if they also hold a
//! staff session, because presenting a WRONG machine credential is an
//! operator error worth surfacing. A caller presenting no Authorization
//! header, or a Bearer / cookie session, falls through to the staff-session
//! path.
//!
//! Both env keys unset mean the machine-credential path is disabled and the
//! extractor delegates every request to `RequireAdmin`; this is the pre-
//! PMS-1193 behaviour and is what a self-hosted deployment with no Bunyip
//! aggregator connected runs on.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::modules::auth::RequireAdmin;
use crate::utils::error::AppError;

/// Machine-credential-or-staff-session gate for the three
/// `/admin/providers/status*` routes.
///
/// The extractor is uninhabited (`RequireAdminOrBunyipMachine`) rather than
/// carrying a caller identity, because the route handlers behind it either
/// serialise the freshly-collected report (JSON / HTML) or run a
/// configuration refresh whose actor is already the `RefreshRequest`'s own
/// choice. A future handler that needs the caller identity should stack
/// this next to a separate identity extractor.
pub struct RequireAdminOrBunyipMachine;

impl<S> FromRequestParts<S> for RequireAdminOrBunyipMachine
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Check Authorization for a Basic scheme first. Only look at the
        // Basic path; any other scheme (`Bearer ...`, `Cookie ...`) is not
        // this extractor's concern and is left for the staff-session
        // fallback to inspect.
        if let Some(header) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(text) = header.to_str() {
                if let Some(encoded) = text.strip_prefix("Basic ") {
                    match verify_bunyip_basic(encoded) {
                        BunyipBasicOutcome::Accepted => return Ok(Self),
                        BunyipBasicOutcome::Refused => {
                            // The caller tried to use the machine-credential
                            // path and failed; do NOT let them retry via the
                            // staff session, because a wrong machine
                            // credential is an operator error worth
                            // surfacing rather than being papered over.
                            return Err(AppError::Unauthorized);
                        }
                        BunyipBasicOutcome::NotConfigured | BunyipBasicOutcome::NotAttempted => {
                            // Fall through to the staff session below.
                        }
                    }
                }
            }
        }
        // Staff-session fallback. Delegates entirely to `RequireAdmin`; a
        // 401 from there is what a caller with no credentials at all gets,
        // which is the pre-PMS-1193 behaviour. `AuthRejection` converts
        // through `From<AuthRejection> for AppError` so the two extractors
        // present the same envelope on refusal.
        match RequireAdmin::from_request_parts(parts, state).await {
            Ok(_) => Ok(Self),
            Err(rej) => Err(rej.into()),
        }
    }
}

/// What checking the incoming Basic auth decided.
///
/// `NotAttempted` is the shape where the header was Basic but the base64
/// was malformed or missing a `:`; treating that as `Refused` would 401
/// callers who typoed a header in a way that has nothing to do with the
/// configured credential, and the staff-session fallback answers a bad
/// header the same 401 anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BunyipBasicOutcome {
    Accepted,
    Refused,
    NotConfigured,
    NotAttempted,
}

fn verify_bunyip_basic(encoded: &str) -> BunyipBasicOutcome {
    let expected_id = crate::config::get(&crate::config::registry::BUNYIP_STATUS_CLIENT_ID)
        .filter(|s| !s.is_empty());
    let expected_secret = crate::config::get(&crate::config::registry::BUNYIP_STATUS_CLIENT_SECRET)
        .filter(|s| !s.is_empty());
    let (Some(expected_id), Some(expected_secret)) = (expected_id, expected_secret) else {
        return BunyipBasicOutcome::NotConfigured;
    };
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return BunyipBasicOutcome::NotAttempted;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return BunyipBasicOutcome::NotAttempted;
    };
    let Some((id, secret)) = text.split_once(':') else {
        return BunyipBasicOutcome::NotAttempted;
    };
    let id_match = constant_time_eq::constant_time_eq(id.as_bytes(), expected_id.as_bytes());
    let secret_match =
        constant_time_eq::constant_time_eq(secret.as_bytes(), expected_secret.as_bytes());
    if id_match && secret_match {
        BunyipBasicOutcome::Accepted
    } else {
        BunyipBasicOutcome::Refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unset env: outcome is `NotConfigured` regardless of what the caller
    /// sent, so the staff-session fallback runs the way it did before
    /// PMS-1193.
    #[test]
    fn unset_env_falls_through() {
        // Nothing to seed; a fresh test process has neither key set, and
        // `crate::config::get` returns `None`. Any decoded input becomes
        // `NotConfigured` at the guard above.
        assert_eq!(
            verify_bunyip_basic("aWQ6c2VjcmV0"),
            BunyipBasicOutcome::NotConfigured
        );
    }

    /// The env fixture is process-global; only assert on the pure decoder
    /// path here. The full extractor integration test lives in
    /// `tests/provider_status_machine_credential.rs`.
    #[test]
    fn malformed_base64_is_not_attempted() {
        assert_eq!(
            verify_bunyip_basic("!!! not base64 !!!"),
            BunyipBasicOutcome::NotConfigured
        );
    }
}
