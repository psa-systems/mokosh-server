//! Typed feature flags on top of the configuration provider (PMS-983).
//!
//! Mokosh gates behaviour three ways: cargo features (`multi-tenant`,
//! `server`) at compile time, `ModuleGate` for per-tenant module
//! entitlement, and a handful of process-wide switches read from
//! configuration. PMS-983 gives that third kind a shape.
//!
//! A **flag** is a declared application-tier registry key with an
//! explicit default, read through [`crate::config::get`] and thus
//! refreshable via [`crate::config::refresh`]. The parse rule stays
//! with the value type ([`FlagValue`]); the default stays with the
//! flag ([`FlagDefault`]). A caller reads the flag through the ONE
//! read path [`Flag::read`], which trims, parses, and falls back to
//! the flag's default when a raw value did not parse. A typo does
//! not stop the boot: a flag is never security-critical enough for
//! that outcome, mirroring the PMS-902 rule for mail dispatch.
//!
//! # Undeclared keys do not compile
//!
//! [`Flag::new`] takes a `&'static ConfigKey`, and the only way to
//! obtain one is to name a constant in [`crate::config::registry`].
//! A flag naming a key the registry does not declare therefore does
//! not compile: the flag and its registry entry come from one
//! declaration and cannot drift apart.
//!
//! # Scope constraint (PMS-983 vs PMS-1012)
//!
//! This module introduces the read helper. It does NOT rewire an
//! existing consumer that caches a flag value at construction time.
//! [`crate::modules::auth::AuthService::login_approval_enabled`] is
//! the shape: it reads its bool once at boot through
//! `AuthService::with_login_approval` and never re-reads. A change
//! to `LOGIN_APPROVAL_ENABLED` becomes visible on the next server
//! restart there, not on the next [`crate::config::refresh`], even
//! though the flag helper itself is refresh-aware. Making the auth
//! service re-read per check is a separate wiring change that
//! belongs with the admin endpoint work in PMS-1012, because that is
//! the surface that changes a flag at runtime.

use crate::config::{self, registry, ConfigKey};
use crate::utils::deployment::DeploymentMode;

/// A value that can round-trip through configuration.
///
/// The parse rule is per-type and stays with the type, so two flag
/// declarations of the same `T` cannot come to disagree about the
/// meaning of a raw string. Kept small: everything downstream builds
/// on [`Self::parse`] returning `None` for a value the flag's
/// default should stand in for.
pub trait FlagValue: Sized + Copy + PartialEq {
    /// Parse `raw`. `None` means the value did not parse and the
    /// flag's default stands.
    fn parse(raw: &str) -> Option<Self>;
    /// Render this value for a boot record or a status report. Never
    /// used by [`Flag`]'s own `Debug`, which prints the shape of the
    /// default rather than the resolved value; see the module note.
    fn as_str(self) -> &'static str;
}

impl FlagValue for bool {
    /// Case-insensitive `"1" | "true" | "yes"` for true and
    /// `"0" | "false" | "no"` for false; anything else is `None`,
    /// which lets the flag's default stand.
    ///
    /// The true set is exactly what `AppConfig::from_env` matched
    /// against for `LOGIN_APPROVAL_ENABLED` before PMS-983, so the
    /// migration onto [`Flag`] preserves the shipping behaviour.
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        if self {
            "true"
        } else {
            "false"
        }
    }
}

/// A flag's default, resolved at read time.
///
/// [`Self::PerProfile`] reads [`DeploymentMode`] each time the
/// default is consulted rather than freezing a mode at
/// construction. The mode is process-global and only changes across
/// restarts, so this costs one env read per flag read and keeps a
/// flag's default in step with the deployment shape without
/// threading the mode through every caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagDefault<T: FlagValue> {
    /// One default for every deployment shape.
    Constant(T),
    /// A different default per hosting profile. Resolved at read
    /// time against [`DeploymentMode`].
    PerProfile {
        /// The default for a `self-hosted` deployment.
        self_hosted: T,
        /// The default for a `saas` deployment.
        saas: T,
    },
}

/// One declared feature flag.
///
/// Reading through [`Flag::read`] is what makes a flag refreshable:
/// the value comes from the current [`crate::config::Generation`],
/// so a [`crate::config::refresh`] takes effect on the next read.
///
/// # Debug
///
/// [`Flag`]'s `Debug` deliberately prints the key name and the shape
/// of the default (`Constant` or `PerProfile`), never the flag's
/// resolved value. A boolean is not sensitive on its own, but the
/// pattern holds for future non-bool flags whose value may be.
pub struct Flag<T: FlagValue> {
    key: &'static ConfigKey,
    default: FlagDefault<T>,
}

impl<T: FlagValue> Flag<T> {
    /// Declare a flag over a registered key.
    ///
    /// `key` is a `&'static ConfigKey`, so an undeclared key is a
    /// compile error; there is no way to construct one outside the
    /// [`crate::config::registry`] macro.
    pub const fn new(key: &'static ConfigKey, default: FlagDefault<T>) -> Self {
        Self { key, default }
    }

    /// The registered key backing this flag.
    pub fn key(&self) -> &'static ConfigKey {
        self.key
    }

    /// The parsed value, else the flag's resolved default.
    ///
    /// This is the ONE read path for a flag. A caller who took the
    /// raw [`Option<String>`] from [`crate::config::get`] and parsed
    /// it themselves would be reinventing the fallback rule, which
    /// is exactly what this helper keeps in one place. A blank
    /// value (trimmed length zero) is treated as unset for the same
    /// reason [`AppConfig::from_env`] treats blanks as unset: a
    /// compose key forwarded but unset arrives as `""` (PMS-836).
    pub fn read(&self) -> T {
        match config::get(self.key) {
            Some(raw) if !raw.trim().is_empty() => match T::parse(&raw) {
                Some(value) => value,
                None => self.resolved_default(),
            },
            _ => self.resolved_default(),
        }
    }

    /// The default that applies to this deployment, with a
    /// [`FlagDefault::PerProfile`] resolved against the current
    /// hosting profile.
    ///
    /// Uses the LENIENT [`DeploymentMode::from_env`] rather than the
    /// strict `from_env_for_providers` reader. A flag is never
    /// security-critical enough for a fatal boot on a typo in
    /// `MOKOSH_DEPLOYMENT_MODE`, and PMS-902 already argued the case
    /// for the lenient reader when the answer only gates behaviour
    /// with a safe default.
    pub fn resolved_default(&self) -> T {
        match self.default {
            FlagDefault::Constant(value) => value,
            FlagDefault::PerProfile { self_hosted, saas } => {
                if DeploymentMode::from_env().is_saas() {
                    saas
                } else {
                    self_hosted
                }
            }
        }
    }

    /// Which provider held this flag's raw value in the current
    /// generation, or `None` when no provider did.
    ///
    /// Mirror of [`crate::config::served_by`], scoped to this flag
    /// so the future provider-status report (PMS-1012) can render
    /// one line per flag naming its source.
    pub fn served_by(&self) -> Option<&'static str> {
        config::served_by(self.key)
    }
}

impl<T: FlagValue> std::fmt::Debug for Flag<T> {
    /// The key name and the shape of the default. Never the resolved
    /// value: see the module note on `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let default_shape = match self.default {
            FlagDefault::Constant(_) => "Constant",
            FlagDefault::PerProfile { .. } => "PerProfile",
        };
        f.debug_struct("Flag")
            .field("key", &self.key.name())
            .field("default", &default_shape)
            .finish()
    }
}

/// PMS-983: the organizations feature.
///
/// A SaaS deployment has multi-user organizations enabled by
/// default, matching the current shipping behaviour on nc-01 and
/// c-01. A self-hosted deployment starts with organizations off,
/// matching the single-user default the customer image ships with
/// today.
pub static ORGANIZATIONS_ENABLED: Flag<bool> = Flag::new(
    &registry::ORGANIZATIONS_ENABLED,
    FlagDefault::PerProfile {
        self_hosted: false,
        saas: true,
    },
);

/// PMS-658 / PMS-983: opt-in gate on the suspicious-login
/// notify-and-approve flow.
///
/// Off by default in both hosting profiles because turning it on
/// can withhold a login (PMS-658), so it is enabled per deployment
/// for a staged rollout. Migrated from an inline `config::get`
/// parse at `AppConfig::from_env` onto [`Flag`] without changing
/// the shipping default or the [`crate::modules::auth::AuthService`]
/// plumbing it feeds (PMS-1012 is what makes the stored bool
/// refresh-aware).
pub static LOGIN_APPROVAL_ENABLED: Flag<bool> = Flag::new(
    &registry::LOGIN_APPROVAL_ENABLED,
    FlagDefault::Constant(false),
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Tier;
    use std::sync::Mutex;

    /// Serialise every test that mutates the process environment,
    /// so two of them cannot race a `set_var` / `refresh` pair
    /// against each other. The configuration provider is
    /// process-global and shared between these tests; a
    /// synchronous `Mutex` is enough because none of these tests
    /// are async. No other test in this crate writes the variables
    /// exercised here (`LOGIN_APPROVAL_ENABLED`,
    /// `MOKOSH_DEPLOYMENT_MODE`), so serialising within the module
    /// is sufficient.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII: remove `keys` on construction and again on drop, then
    /// refresh the configuration generation. A test failure cannot
    /// then leak a variable into a sibling.
    struct EnvGuard {
        keys: Vec<&'static str>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            for key in keys {
                std::env::remove_var(key);
            }
            let _ = config::refresh();
            Self {
                keys: keys.to_vec(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in &self.keys {
                std::env::remove_var(key);
            }
            let _ = config::refresh();
        }
    }

    /// Every truthy and falsy spelling parses, and casing and
    /// padding do not matter. Everything else asks the flag's
    /// default to stand in.
    #[test]
    fn bool_parses_the_documented_truthy_and_falsy_spellings() {
        for raw in ["1", "true", "yes", "TRUE", "Yes", "  true  "] {
            assert_eq!(<bool as FlagValue>::parse(raw), Some(true), "{raw:?}");
        }
        for raw in ["0", "false", "no", "FALSE", "No", "  false  "] {
            assert_eq!(<bool as FlagValue>::parse(raw), Some(false), "{raw:?}");
        }
    }

    #[test]
    fn bool_returns_none_for_a_bogus_or_blank_value() {
        for raw in ["maybe", "on", "off", "  ", ""] {
            assert_eq!(<bool as FlagValue>::parse(raw), None, "{raw:?}");
        }
    }

    /// A flag key must stay on the Application tier: the whole
    /// point of the helper is refresh visibility, and a Bootstrap
    /// key resolves once per process and is carried across a
    /// refresh unchanged.
    #[test]
    fn every_shipping_flag_names_an_application_tier_key() {
        assert_eq!(LOGIN_APPROVAL_ENABLED.key().tier(), Tier::Application);
        assert_eq!(ORGANIZATIONS_ENABLED.key().tier(), Tier::Application);
    }

    /// The Debug print carries the key name and the SHAPE of the
    /// default. The resolved value is deliberately never on it;
    /// see the module note on `Debug`.
    #[test]
    fn debug_shows_the_key_and_the_shape_of_the_default_never_the_value() {
        let printed = format!("{LOGIN_APPROVAL_ENABLED:?}");
        assert!(printed.contains("LOGIN_APPROVAL_ENABLED"), "{printed}");
        assert!(printed.contains("Constant"), "{printed}");
        assert!(!printed.contains("true"), "{printed}");
        assert!(!printed.contains("false"), "{printed}");

        let printed = format!("{ORGANIZATIONS_ENABLED:?}");
        assert!(printed.contains("ORGANIZATIONS_ENABLED"), "{printed}");
        assert!(printed.contains("PerProfile"), "{printed}");
    }

    /// A `Constant` default stands when no provider holds the
    /// key: this is what `login_approval_enabled = false` means in
    /// a fresh deployment.
    #[test]
    fn a_constant_default_is_used_when_no_provider_holds_the_key() {
        let _serial = ENV_LOCK.lock().expect("env lock is never poisoned");
        let _cleanup = EnvGuard::new(&["LOGIN_APPROVAL_ENABLED"]);

        assert!(!LOGIN_APPROVAL_ENABLED.read());
    }

    /// A `PerProfile` default resolves against the current
    /// deployment mode. Unset means self-hosted (PMS-902), which
    /// takes the `self_hosted` arm; `saas` takes the `saas` arm.
    #[test]
    fn a_per_profile_default_resolves_against_the_deployment_mode() {
        let _serial = ENV_LOCK.lock().expect("env lock is never poisoned");
        let _cleanup = EnvGuard::new(&["MOKOSH_DEPLOYMENT_MODE"]);

        assert!(
            !ORGANIZATIONS_ENABLED.resolved_default(),
            "unset MOKOSH_DEPLOYMENT_MODE resolves to self-hosted, which takes the self_hosted arm"
        );

        std::env::set_var("MOKOSH_DEPLOYMENT_MODE", "saas");
        assert!(
            ORGANIZATIONS_ENABLED.resolved_default(),
            "saas mode flips the per-profile default to the saas arm"
        );
    }

    /// Every truthy raw value that the current inline read matched
    /// on still resolves true; every falsy one still resolves
    /// false. This preserves the pre-PMS-983 shipping behaviour.
    #[test]
    fn an_explicit_raw_value_beats_the_default_for_true_and_for_false() {
        let _serial = ENV_LOCK.lock().expect("env lock is never poisoned");
        let _cleanup = EnvGuard::new(&["LOGIN_APPROVAL_ENABLED"]);

        for raw in ["1", "true", "yes"] {
            std::env::set_var("LOGIN_APPROVAL_ENABLED", raw);
            let _ = config::refresh();
            assert!(LOGIN_APPROVAL_ENABLED.read(), "{raw:?}");
        }
        for raw in ["0", "false", "no"] {
            std::env::set_var("LOGIN_APPROVAL_ENABLED", raw);
            let _ = config::refresh();
            assert!(!LOGIN_APPROVAL_ENABLED.read(), "{raw:?}");
        }
    }

    /// A bogus value falls back to the flag's default (rather than
    /// a boot failure or a silent flip), and a whitespace-only
    /// value is treated as unset: the read trims before parsing,
    /// so a compose key forwarded but unset (PMS-836) resolves
    /// exactly as a truly-absent one.
    #[test]
    fn a_bogus_or_blank_value_falls_back_to_the_flag_default() {
        let _serial = ENV_LOCK.lock().expect("env lock is never poisoned");
        let _cleanup = EnvGuard::new(&["LOGIN_APPROVAL_ENABLED"]);

        std::env::set_var("LOGIN_APPROVAL_ENABLED", "maybe");
        let _ = config::refresh();
        assert!(!LOGIN_APPROVAL_ENABLED.read());

        std::env::set_var("LOGIN_APPROVAL_ENABLED", "  ");
        let _ = config::refresh();
        assert!(!LOGIN_APPROVAL_ENABLED.read());
    }

    /// The refresh contract in executable form: mutate, refresh,
    /// read. Nothing else has to happen for a flag change to be
    /// seen by [`Flag::read`]; a consumer that caches the value at
    /// construction (`AuthService`) still takes a restart, which is
    /// PMS-1012.
    #[test]
    fn a_refresh_makes_a_new_value_visible_to_flag_read() {
        let _serial = ENV_LOCK.lock().expect("env lock is never poisoned");
        let _cleanup = EnvGuard::new(&["LOGIN_APPROVAL_ENABLED"]);

        assert!(!LOGIN_APPROVAL_ENABLED.read());

        std::env::set_var("LOGIN_APPROVAL_ENABLED", "true");
        let _ = config::refresh();
        assert!(LOGIN_APPROVAL_ENABLED.read());
    }

    /// `served_by` names the provider that held the flag's raw
    /// value in the current generation. The environment provider
    /// is the process-wide default, so a variable set in env
    /// resolves to it; a variable set nowhere resolves to no
    /// provider at all.
    #[test]
    fn served_by_names_the_provider_that_held_the_key() {
        let _serial = ENV_LOCK.lock().expect("env lock is never poisoned");
        let _cleanup = EnvGuard::new(&["LOGIN_APPROVAL_ENABLED"]);

        std::env::set_var("LOGIN_APPROVAL_ENABLED", "true");
        let _ = config::refresh();
        assert_eq!(LOGIN_APPROVAL_ENABLED.served_by(), Some("environment"));

        std::env::remove_var("LOGIN_APPROVAL_ENABLED");
        let _ = config::refresh();
        assert_eq!(LOGIN_APPROVAL_ENABLED.served_by(), None);
    }
}
