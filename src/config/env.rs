//! The process environment as a configuration provider (PMS-982).
//!
//! The first and default provider, and deliberately the dullest one: it reads
//! exactly what every call site read before the seam existed, so a deployment
//! that configures nothing behaves identically.

use async_trait::async_trait;

use super::{ConfigProvider, Enumeration, REGISTRY};
use crate::utils::deployment::provider;

/// Reads `std::env`. Stateless, so it is cheap to build and safe to share.
pub struct EnvProvider;

#[async_trait]
impl ConfigProvider for EnvProvider {
    fn name(&self) -> &'static str {
        provider::ENVIRONMENT
    }

    fn get(&self, key: &str) -> Option<String> {
        match std::env::var(key) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            // Set but not readable as UTF-8. Answering `None` alone would make
            // a configured value indistinguishable from an unset one, so the
            // operator hears about the variable they set and cannot be used.
            Err(err) => {
                tracing::error!(
                    key,
                    error = %err,
                    "environment variable is set but unreadable; treating it as unset"
                );
                None
            }
        }
    }

    /// Presence without decoding, so a variable this provider cannot read
    /// still counts as held by it in a presence matrix.
    fn has(&self, key: &str) -> bool {
        std::env::var_os(key).is_some()
    }

    /// The DECLARED keys the environment holds, never every variable in the
    /// process. A presence matrix is about configuration this application
    /// reads; `PATH` and `HOSTNAME` are not that, and listing them would make
    /// the report unreadable and leak the host's own environment into it.
    fn list(&self) -> Enumeration {
        Enumeration::Keys(
            REGISTRY
                .iter()
                .filter(|key| self.has(key.name()))
                .map(|key| key.name().to_string())
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provider_names_itself_as_the_environment() {
        assert_eq!(EnvProvider.name(), "environment");
    }

    /// The environment can enumerate, so it never reports `Unsupported`; that
    /// answer is reserved for a provider that genuinely cannot see its own
    /// contents.
    #[test]
    fn the_environment_can_enumerate_and_lists_only_declared_keys() {
        let listed = EnvProvider.list();
        let keys = listed.keys().expect("the environment can be enumerated");
        for name in keys {
            assert!(
                REGISTRY.iter().any(|key| key.name() == name),
                "{name} is not a declared key"
            );
        }
    }

    /// A variable that is genuinely absent reads as absent. Uses a name no
    /// registry key uses and no test sets, so it cannot race a sibling.
    #[test]
    fn an_absent_variable_has_no_value() {
        assert_eq!(EnvProvider.get("PMS982_NAME_THAT_IS_NEVER_SET"), None);
        assert!(!EnvProvider.has("PMS982_NAME_THAT_IS_NEVER_SET"));
    }
}
