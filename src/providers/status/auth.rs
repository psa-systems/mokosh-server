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
                    let configured = configured_credential();
                    let expected = configured
                        .as_ref()
                        .map(|(id, secret)| (id.as_str(), secret.as_str()));
                    match verify_bunyip_basic(encoded, expected) {
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

/// The configured machine credential, or `None` when the path is disabled.
///
/// PMS-1218: the ONLY configuration read on this path, kept out of
/// [`verify_bunyip_basic`] so the decision itself is a pure function. It used
/// to read the two keys inline, which made every outcome depend on
/// process-global state and made the unit tests below assert on whatever a
/// concurrently running test had left in the environment.
fn configured_credential() -> Option<(String, String)> {
    let id = crate::config::get(&crate::config::registry::BUNYIP_STATUS_CLIENT_ID)
        .filter(|s| !s.is_empty())?;
    let secret = crate::config::get(&crate::config::registry::BUNYIP_STATUS_CLIENT_SECRET)
        .filter(|s| !s.is_empty())?;
    Some((id, secret))
}

/// Decide what an incoming Basic header means, given the configured
/// credential.
///
/// Pure: `expected` is passed in rather than read here, so the outcome depends
/// on nothing but the two arguments. That is what lets the tests below name a
/// case and assert it, instead of asserting whichever answer the environment
/// happened to hold.
fn verify_bunyip_basic(encoded: &str, expected: Option<(&str, &str)>) -> BunyipBasicOutcome {
    let Some((expected_id, expected_secret)) = expected else {
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

    const CONFIGURED: Option<(&str, &str)> = Some(("bunyip-status", "s3cret-value"));

    /// No configured credential: the outcome is `NotConfigured` whatever the
    /// caller sent, so the staff-session fallback runs the way it did before
    /// PMS-1193.
    #[test]
    fn an_unconfigured_credential_falls_through() {
        assert_eq!(
            verify_bunyip_basic("aWQ6c2VjcmV0", None),
            BunyipBasicOutcome::NotConfigured
        );
    }

    /// PMS-1218: a malformed header is `NotAttempted`, which is what this
    /// test has always been named for and could not previously assert.
    ///
    /// The decision used to read the configured credential itself, so with
    /// the keys unset every input short-circuited to `NotConfigured` before
    /// the decoder ran - and the assertion said `NotConfigured` while the
    /// name said otherwise. Which one was true depended on whether a
    /// concurrently running test in `route.rs` had set the environment,
    /// which is exactly how this flaked.
    #[test]
    fn malformed_base64_is_not_attempted() {
        for malformed in ["!!! not base64 !!!", "bm9jb2xvbg==", ""] {
            assert_eq!(
                verify_bunyip_basic(malformed, CONFIGURED),
                BunyipBasicOutcome::NotAttempted,
                "{malformed:?}"
            );
        }
    }

    /// The two outcomes that decide a request, asserted against a credential
    /// this test owns rather than one the process happens to hold.
    #[test]
    fn a_matching_credential_is_accepted_and_a_wrong_one_is_refused() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let encode = |pair: &str| STANDARD.encode(pair);
        assert_eq!(
            verify_bunyip_basic(&encode("bunyip-status:s3cret-value"), CONFIGURED),
            BunyipBasicOutcome::Accepted
        );
        for wrong in ["bunyip-status:wrong", "wrong:s3cret-value", "wrong:wrong"] {
            assert_eq!(
                verify_bunyip_basic(&encode(wrong), CONFIGURED),
                BunyipBasicOutcome::Refused,
                "{wrong}"
            );
        }
    }
}
