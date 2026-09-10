//! Local (legacy HS256 cookie / bearer) auth provider adapter (PMS-981).
//!
//! An adapter over [`crate::modules::auth::middleware`] and
//! [`crate::modules::auth::service::AuthService`]. Like
//! [`super::bunyip::BunyipOidcProvider`], this holds one boolean and
//! nothing else from the request-authentication path: the provider is
//! dormant in this change and `create_api_router` continues to mount the
//! underlying middleware exactly as it did before.
//!
//! `is_available` is a constant `true`. The local path only needs the
//! process itself and its Postgres, both of which the whole application
//! already depends on: a deployment where local is unreachable is a
//! deployment that isn't running at all, so there is no "available or not"
//! state to model here.

use crate::utils::deployment::provider;

use super::AuthProvider;

/// The legacy cookie / bearer path, named.
#[derive(Clone, Copy, Debug)]
pub struct LocalProvider {
    is_enabled: bool,
}

impl LocalProvider {
    /// Construct the adapter. `is_enabled` reflects the resolved
    /// [`super::AuthProviderSelection`].
    pub fn new(is_enabled: bool) -> Self {
        Self { is_enabled }
    }
}

impl AuthProvider for LocalProvider {
    fn name(&self) -> &'static str {
        provider::LOCAL
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn is_available(&self) -> bool {
        // The credential path is the process and its database. Both are
        // preconditions for booting at all, so availability is not a
        // separate fact from having reached this line.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names come from `crate::utils::deployment::provider`, so the name
    /// on the wire (`AUTH_PROVIDERS=local`) and the name here cannot
    /// drift.
    #[test]
    fn the_name_is_the_shared_provider_constant() {
        let adapter = LocalProvider::new(true);
        assert_eq!(adapter.name(), provider::LOCAL);
        assert_eq!(adapter.name(), "local");
    }

    /// Local is always available; only enablement varies with the
    /// resolved selection.
    #[test]
    fn availability_is_a_constant_true() {
        assert!(LocalProvider::new(true).is_available());
        assert!(LocalProvider::new(false).is_available());
    }

    #[test]
    fn enabled_follows_the_selection() {
        assert!(LocalProvider::new(true).is_enabled());
        assert!(!LocalProvider::new(false).is_enabled());
    }
}
