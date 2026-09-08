//! Every configuration key this application reads, declared with its tier.
//!
//! The registry is the half of PMS-982 that the abstraction alone does not
//! give you. Bunyip had a working Infisical client and still served secrets
//! from the database, because nothing said which keys existed or forced the
//! read through the seam. A key that is not declared here cannot be asked for:
//! [`crate::config::get`] takes a `&'static ConfigKey`, and the only way to
//! obtain one is to name a constant below.
//!
//! `.env.example` is the rendered, operator-facing form of this list, and
//! `scripts/check-env-example.nu` fails the build when the two disagree, in
//! either direction. That is what makes a computed-key read visible: PMS-982
//! found `BrandingAssetStore::max_bytes` reading a name a literal-only scanner
//! could not see, and five of its six keys were in neither `.env.example` nor
//! `compose.dev.yml`.
//!
//! Keys read OUTSIDE the provider are not here. They are the bootstrap entry
//! points and the providers of record, each listed in
//! [`crate::config::guard::ENTRY_POINTS`] with the reason it may go around the
//! seam.
//!
//! # Feature annotation (PMS-1075)
//!
//! A key may carry an optional `feature = "..."` line beside its tier. When it
//! does, boot warns if no provider held the key, naming the feature that will
//! not work. When it does not, an unresolved key is legitimately unset and boot
//! stays silent about it.
//!
//! The reason the default is `None`: warning on every unresolved key would
//! warn on every boot of a correctly configured deployment. Most of the
//! declared keys are legitimately unset - `SMTP_USERNAME`,
//! `ABUSE_CONTACT_EMAIL`, `IP2LOCATION_DB_PATH`, `OUTBOUND_PRIVATE_ALLOWLIST`,
//! the six branding caps - and a warning that fires on a healthy deployment
//! is one operators learn to skip, which makes the real one invisible, the
//! failure mode PMS-1009 exists to remove. So a key carries a `feature` only
//! when its absence disables a specific capability that no boot check already
//! fatal-fails on, and the current registry marks none: `ENCRYPTION_KEY` and
//! `JWT_SECRET` already boot-fail through `resolve_secret`, `SMTP_HOST` unset
//! selects `LogMailer` on purpose, `LOGIN_APPROVAL_ENABLED` unset is off by
//! design (PMS-658), and every other candidate carries a documented default
//! an operator selects on purpose. Keys are annotated here as features
//! surface where absence is silent-and-wrong.

use std::fmt;

/// When a key resolves, per the tier split in `docs/providers.md`.
///
/// The line is bootstrap ORDER, not how secret a value is: bootstrap is what a
/// provider is made from, so it cannot be served by one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Resolved exactly once per process, and carried across a
    /// [`crate::config::refresh`] unchanged. Changing one needs a restart,
    /// because a provider built from it is already holding the old value.
    Bootstrap,
    /// Re-resolved by every refresh. Everything else the deployment
    /// configures.
    Application,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Bootstrap => "bootstrap",
            Tier::Application => "application",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One declared key: the name a provider is asked for, its tier, and the
/// feature its absence disables (when any).
///
/// Constructed only by the [`declare_keys`] macro below, so a key and its
/// registry entry come from one declaration and cannot drift apart.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigKey {
    name: &'static str,
    tier: Tier,
    /// PMS-1075: the sentence naming what stops working when no provider
    /// holds this key. `None` means the key is legitimately unset and its
    /// absence is not something to warn about at boot; see the module-level
    /// note for why the default is silence.
    feature: Option<&'static str>,
}

impl ConfigKey {
    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// What stops working when no provider holds this key. `None` means the
    /// key is legitimately unset when nothing configures it, so boot is
    /// silent about the absence.
    pub fn feature(&self) -> Option<&'static str> {
        self.feature
    }

    /// Test-only constructor: the real registry marks no key with a feature
    /// today (see the module note above), so PMS-1075's filter behaviour is
    /// exercised through a fabricated key whose name never leaks into the
    /// shipping [`REGISTRY`]. Kept `pub(crate)` so it cannot be used to fake
    /// a runtime key outside this crate.
    #[cfg(test)]
    pub(crate) const fn for_test_with_feature(
        name: &'static str,
        tier: Tier,
        feature: &'static str,
    ) -> Self {
        Self {
            name,
            tier,
            feature: Some(feature),
        }
    }
}

impl fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

/// Declare a key and its registry entry in one statement.
///
/// The macro exists so [`REGISTRY`] cannot fall out of step with the constants:
/// there is no way to add one without the other. Each declaration reads as
/// `Tier NAME = "NAME";` and may be preceded by doc comments and, optionally,
/// a single `#[feature = "sentence"]` attribute (PMS-1075) that boot uses to
/// name what will not work if no provider holds the key. Keys without a
/// feature attribute are legitimately-unset by design; see the module-level
/// note for why silence is the default.
macro_rules! declare_keys {
    ($(
        $(#[doc = $doc:literal])*
        $(#[feature = $feature:literal])?
        $tier:ident $ident:ident = $name:literal;
    )*) => {
        $(
            $(#[doc = $doc])*
            pub static $ident: ConfigKey = ConfigKey {
                name: $name,
                tier: Tier::$tier,
                feature: declare_keys!(@feature $($feature)?),
            };
        )*

        /// Every declared key, in declaration order. The boot resolution walks
        /// this, `provider-status` will render it, and
        /// `scripts/check-env-example.nu` compares it against `.env.example`.
        pub static REGISTRY: &[&ConfigKey] = &[$(&$ident),*];
    };
    (@feature $feature:literal) => { Some($feature) };
    (@feature) => { None };
}

declare_keys! {
    // -- Bootstrap: what a provider is made from ------------------------------
    // A configuration provider backed by the database (PMS-987) is built from
    // these, so they cannot be served by one without asking the database for
    // the credential used to reach the database.

    /// Privileged (`mokosh_migrator`) connection string.
    Bootstrap DATABASE_URL = "DATABASE_URL";
    /// Request-serving (`mokosh_app`) connection string (PMS-285).
    Bootstrap MOKOSH_APP_DATABASE_URL = "MOKOSH_APP_DATABASE_URL";
    /// AES-256-GCM key for at-rest encryption, which a database-backed
    /// provider would need in order to read anything it stored.
    Bootstrap ENCRYPTION_KEY = "ENCRYPTION_KEY";

    // -- Application: the server's own shape ---------------------------------

    Application ENVIRONMENT = "ENVIRONMENT";
    Application HOST = "HOST";
    Application PORT = "PORT";
    Application BASE_URL = "BASE_URL";
    Application RUN_MIGRATIONS = "RUN_MIGRATIONS";
    Application JWT_SECRET = "JWT_SECRET";
    Application BUNYIP_WEBHOOK_SECRET = "BUNYIP_WEBHOOK_SECRET";
    Application CLIENT_ORIGIN = "CLIENT_ORIGIN";
    Application CORS_ORIGIN = "CORS_ORIGIN";
    Application SPA_BASE_URL = "SPA_BASE_URL";
    Application PUBLIC_API_BASE_URL = "PUBLIC_API_BASE_URL";
    Application ABUSE_CONTACT_EMAIL = "ABUSE_CONTACT_EMAIL";
    Application MOKOSH_MAX_TENANTS = "MOKOSH_MAX_TENANTS";
    Application MOKOSH_UPDATE_CHECK_URL = "MOKOSH_UPDATE_CHECK_URL";

    // -- Mail ----------------------------------------------------------------

    Application SMTP_HOST = "SMTP_HOST";
    Application SMTP_PORT = "SMTP_PORT";
    Application SMTP_USERNAME = "SMTP_USERNAME";
    Application SMTP_PASSWORD = "SMTP_PASSWORD";
    Application SMTP_FROM = "SMTP_FROM";
    Application SMTP_TLS = "SMTP_TLS";

    // -- Authentication ------------------------------------------------------

    Application OIDC_ISSUER = "OIDC_ISSUER";
    Application OIDC_AUDIENCE = "OIDC_AUDIENCE";
    Application OIDC_JWKS_CACHE_TTL_SECS = "OIDC_JWKS_CACHE_TTL_SECS";
    Application OIDC_LEEWAY_SECONDS = "OIDC_LEEWAY_SECONDS";
    Application OIDC_DEFAULT_TENANT_ID = "OIDC_DEFAULT_TENANT_ID";
    Application ADMIN_EMAIL = "ADMIN_EMAIL";
    Application ADMIN_PASSWORD = "ADMIN_PASSWORD";
    Application LOGIN_APPROVAL_ENABLED = "LOGIN_APPROVAL_ENABLED";

    // -- Feature flags (PMS-983) ---------------------------------------------
    // Reached through `crate::config::flags`, so the parse rule and the
    // default live with the flag rather than at every read site. No feature
    // annotation: an unset key is the flag's default and the boot log stays
    // silent, matching the registry convention.

    /// PMS-983: the organizations feature. Read through
    /// `crate::config::flags::ORGANIZATIONS_ENABLED`, which defaults per
    /// hosting profile (off on self-hosted, on for SaaS).
    Application ORGANIZATIONS_ENABLED = "ORGANIZATIONS_ENABLED";
    Application IP2LOCATION_DB_PATH = "IP2LOCATION_DB_PATH";
    Application IP2PROXY_DB_PATH = "IP2PROXY_DB_PATH";

    // -- Network ------------------------------------------------------------

    Application TRUSTED_PROXY_CIDR = "TRUSTED_PROXY_CIDR";
    Application OUTBOUND_PRIVATE_ALLOWLIST = "OUTBOUND_PRIVATE_ALLOWLIST";
    /// The in-network Infisical base the readiness probe reports on. Blank
    /// means unconfigured (PMS-707), never a failing probe. The Infisical
    /// SECRET provider reads its own copy at its entry point, because a
    /// provider cannot be built out of values served by itself.
    Application INFISICAL_ADDRESS = "INFISICAL_ADDRESS";

    // -- Payment provider hosts ----------------------------------------------
    // Overridable so an integration test can point the calls at a stub.

    Application STRIPE_API_BASE = "STRIPE_API_BASE";
    Application PAYPAL_API_BASE = "PAYPAL_API_BASE";

    // -- Uploads -------------------------------------------------------------
    // `ATTACHMENT_DIR` is also read by `crate::storage`, which is a provider of
    // record and reads it at its entry point; branding asks for it here.

    Application ATTACHMENT_DIR = "ATTACHMENT_DIR";
    Application ATTACHMENT_MAX_BYTES = "ATTACHMENT_MAX_BYTES";
    Application KB_ATTACHMENT_MAX_BYTES = "KB_ATTACHMENT_MAX_BYTES";

    // The six `BrandingAssetStore::max_bytes` caps. They are a closed match on
    // `(AssetScope, BrandAssetKind)`, which is why all six are declarable and
    // why a literal-only scan of the read site saw none of them.
    Application TENANT_LOGO_MAX_BYTES = "TENANT_LOGO_MAX_BYTES";
    Application BRANDING_TENANT_FAVICON_MAX_BYTES = "BRANDING_TENANT_FAVICON_MAX_BYTES";
    Application BRANDING_TENANT_BACKGROUND_MAX_BYTES = "BRANDING_TENANT_BACKGROUND_MAX_BYTES";
    Application BRANDING_COMPANY_LOGO_MAX_BYTES = "BRANDING_COMPANY_LOGO_MAX_BYTES";
    Application BRANDING_COMPANY_FAVICON_MAX_BYTES = "BRANDING_COMPANY_FAVICON_MAX_BYTES";
    Application BRANDING_COMPANY_BACKGROUND_MAX_BYTES = "BRANDING_COMPANY_BACKGROUND_MAX_BYTES";

    // -- Seeding -------------------------------------------------------------

    Application MOKOSH_SEED_TENANT_ID = "MOKOSH_SEED_TENANT_ID";
    Application MOKOSH_DEMO_SEED = "MOKOSH_DEMO_SEED";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A duplicate name would make one key shadow the other in the resolved
    /// generation, and the two constants would silently share a value.
    #[test]
    fn every_declared_name_is_unique() {
        let mut seen = BTreeSet::new();
        for key in REGISTRY {
            assert!(
                seen.insert(key.name()),
                "{} is declared twice in the registry",
                key.name()
            );
        }
        assert_eq!(seen.len(), REGISTRY.len());
    }

    /// The name shape `.env.example`, compose and every provider agree on.
    #[test]
    fn every_declared_name_is_an_env_style_name() {
        for key in REGISTRY {
            let name = key.name();
            assert!(!name.is_empty(), "a key may not have an empty name");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{name} must be A-Z, 0-9 and underscore so every provider can address it"
            );
            assert!(
                name.starts_with(|c: char| c.is_ascii_uppercase()),
                "{name} must start with a letter"
            );
        }
    }

    /// The bootstrap tier is small and stated, because every key in it is one
    /// a later provider cannot serve. Growing it silently is how the tier
    /// stops meaning "what a provider is made from".
    #[test]
    fn the_bootstrap_tier_is_exactly_what_a_provider_is_made_from() {
        let bootstrap: Vec<&str> = REGISTRY
            .iter()
            .filter(|k| k.tier() == Tier::Bootstrap)
            .map(|k| k.name())
            .collect();
        assert_eq!(
            bootstrap,
            ["DATABASE_URL", "MOKOSH_APP_DATABASE_URL", "ENCRYPTION_KEY"],
            "adding a bootstrap key means arguing that a provider cannot serve it"
        );
    }
}
