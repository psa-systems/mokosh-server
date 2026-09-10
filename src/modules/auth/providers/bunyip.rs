//! Bunyip Resource-Server auth provider adapter (PMS-981).
//!
//! An adapter over [`crate::modules::auth::oidc_rs`]. Holds two booleans
//! and NOTHING ELSE from the request-authentication path, because this
//! provider is dormant in this change: `create_api_router` continues to
//! mount the underlying verifier through
//! [`crate::modules::auth::middleware::AuthMiddleware::with_bunyip`], and
//! no non-test caller invokes the trait yet (see `providers/mod.rs`).
//!
//! The adapter deliberately does NOT hold a
//! [`crate::modules::auth::oidc_rs::Verifier`]: doing so would couple this
//! module to `reqwest`, `jsonwebtoken` and Bunyip's JWKS cache for
//! reporting a boolean the startup wiring already computed. When the
//! deferred-wiring PR routes real requests through the trait, that PR is
//! free to hold a verifier here; today doing so would only widen the
//! surface without changing behaviour.

use crate::utils::deployment::provider;

use super::AuthProvider;

/// The Bunyip Resource-Server path, named.
///
/// `is_enabled` is set once from the resolved selection (see
/// [`super::AuthProviderSelection`]) and `verifier_present` is what the
/// startup wiring already knows from `bunyip_verifier.is_some()` in
/// `create_api_router`. Both are `Copy` and cheap; a
/// [`BunyipOidcProvider`] is safe to construct from a request handler if
/// the future wiring wants to.
#[derive(Clone, Copy, Debug)]
pub struct BunyipOidcProvider {
    is_enabled: bool,
    verifier_present: bool,
}

impl BunyipOidcProvider {
    /// Construct the adapter. `is_enabled` reflects the resolved
    /// [`super::AuthProviderSelection`]; `verifier_present` is true when
    /// `OIDC_ISSUER` + `OIDC_AUDIENCE` resolved into a
    /// [`crate::modules::auth::oidc_rs::Verifier`] the startup wiring
    /// installed on [`crate::modules::auth::middleware::AuthMiddleware`].
    pub fn new(is_enabled: bool, verifier_present: bool) -> Self {
        Self {
            is_enabled,
            verifier_present,
        }
    }
}

impl AuthProvider for BunyipOidcProvider {
    fn name(&self) -> &'static str {
        provider::BUNYIP
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn is_available(&self) -> bool {
        self.verifier_present
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names come from `crate::utils::deployment::provider`, so the name
    /// on the wire (`AUTH_PROVIDERS=bunyip`) and the name here cannot
    /// drift.
    #[test]
    fn the_name_is_the_shared_provider_constant() {
        let adapter = BunyipOidcProvider::new(true, true);
        assert_eq!(adapter.name(), provider::BUNYIP);
        assert_eq!(adapter.name(), "bunyip");
    }

    /// `is_enabled` reads what the selection said, without inspecting the
    /// verifier state: an operator asking for `bunyip` in `AUTH_PROVIDERS`
    /// on a deployment with no verifier is still asking for it, and the
    /// boot record surfaces the mismatch separately.
    #[test]
    fn enabled_is_independent_of_availability() {
        let enabled_and_available = BunyipOidcProvider::new(true, true);
        assert!(enabled_and_available.is_enabled());
        assert!(enabled_and_available.is_available());

        let enabled_but_unavailable = BunyipOidcProvider::new(true, false);
        assert!(enabled_but_unavailable.is_enabled());
        assert!(!enabled_but_unavailable.is_available());

        let disabled_and_available = BunyipOidcProvider::new(false, true);
        assert!(!disabled_and_available.is_enabled());
        assert!(disabled_and_available.is_available());

        let disabled_and_unavailable = BunyipOidcProvider::new(false, false);
        assert!(!disabled_and_unavailable.is_enabled());
        assert!(!disabled_and_unavailable.is_available());
    }
}
