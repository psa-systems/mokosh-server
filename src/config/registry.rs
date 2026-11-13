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
//! seam; their release facts live in `src/config/variables.toml` (PMS-1442).
//!
//! # Release facts (PMS-1442)
//!
//! Each key states its `since` release and whether boot requires it; `just
//! config-docs` renders both into `docs/configuration.md`.
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
// the two-tier split a provider read is built on.
// SPEC-2.179
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
    /// PMS-1442: the release that introduced the key, e.g. `v0.14.0`.
    since: &'static str,
    /// PMS-1442: the server refuses to start without it outside dev/test.
    required: bool,
    /// PMS-1442: the release that made an older key required; `None` when it
    /// was required from `since` or is optional.
    required_since: Option<&'static str>,
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

    /// The release that introduced this key (`docs/configuration.md`'s
    /// "Added in" column, PMS-1442).
    pub fn since(&self) -> &'static str {
        self.since
    }

    /// Whether the server refuses to start without this key outside
    /// development/dev/test (`docs/configuration.md`'s "Required" column).
    pub fn required(&self) -> bool {
        self.required
    }

    /// The release that made this key required, when that came after `since`.
    pub fn required_since(&self) -> Option<&'static str> {
        self.required_since
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
            since: "v0.1.0",
            required: false,
            required_since: None,
        }
    }
}

impl fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

/// Look up a declared key's tier by name. `None` when `name` is not a
/// declared key at all, which a write-path guard treats as "not bootstrap":
/// an undeclared name cannot be the bootstrap keys this guard exists to
/// stop (see [`Tier::Bootstrap`]'s doc), and refusing it here would be the
/// wrong error for what is actually an unknown-key problem.
///
/// The one place a config-store `set`/`delete` checks before writing
/// (PMS-1228), so the refusal lives once rather than once per provider.
pub fn tier_of(name: &str) -> Option<Tier> {
    REGISTRY
        .iter()
        .find(|key| key.name() == name)
        .map(|key| key.tier())
}

/// Declare a key and its registry entry in one statement.
///
/// The macro exists so [`REGISTRY`] cannot fall out of step with the constants:
/// there is no way to add one without the other. Each declaration reads as
/// `Tier NAME = "NAME", since "vX.Y.Z", optional;` (or `required;`, or
/// `required "vA.B.C";` for a key that became required after it was added,
/// PMS-1442) and may be preceded by doc comments and, optionally,
/// a single `#[feature = "sentence"]` attribute (PMS-1075) that boot uses to
/// name what will not work if no provider holds the key. Keys without a
/// feature attribute are legitimately-unset by design; see the module-level
/// note for why silence is the default.
// the one declaration site a ConfigKey and its Tier/since/required
// facts come from; a flag or a read naming a key it does not emit cannot compile.
// SPEC-6.1, SPEC-6.2: one declaration per key; get() takes only these constants, names are unique A-Z0-9_.
// SPEC-2.178
macro_rules! declare_keys {
    ($(
        $(#[doc = $doc:literal])*
        $(#[feature = $feature:literal])?
        $tier:ident $ident:ident = $name:literal, since $since:literal, $req:ident $($req_since:literal)?;
    )*) => {
        $(
            $(#[doc = $doc])*
            pub static $ident: ConfigKey = ConfigKey {
                name: $name,
                tier: Tier::$tier,
                feature: declare_keys!(@feature $($feature)?),
                since: $since,
                required: declare_keys!(@required $req),
                required_since: declare_keys!(@required_since $($req_since)?),
            };
        )*

        /// Every declared key, in declaration order. The boot resolution walks
        /// this, `provider-status` will render it, and
        /// `scripts/check-env-example.nu` compares it against `.env.example`.
        pub static REGISTRY: &[&ConfigKey] = &[$(&$ident),*];
    };
    (@feature $feature:literal) => { Some($feature) };
    (@feature) => { None };
    (@required required) => { true };
    (@required optional) => { false };
    (@required_since $since:literal) => { Some($since) };
    (@required_since) => { None };
}

// SPEC-6.4, SPEC-6.5: the required set and the since/required_since facts are the per-key tail of each line below.
declare_keys! {
    // -- Bootstrap: what a provider is made from ------------------------------
    // A configuration provider backed by the database (PMS-987) is built from
    // these, so they cannot be served by one without asking the database for
    // the credential used to reach the database.

    // SPEC-6.3, SPEC-6.66: the bootstrap tier is exactly this block (ten keys); DATABASE_URL is required from v0.1.0.
    // SPEC-2.226
    /// Privileged (`mokosh_migrator`) connection string.
    Bootstrap DATABASE_URL = "DATABASE_URL", since "v0.1.0", required;
    // SPEC-6.66: request-serving URL; required since v0.14.0.
    /// Request-serving (`mokosh_app`) connection string (PMS-285).
    Bootstrap MOKOSH_APP_DATABASE_URL = "MOKOSH_APP_DATABASE_URL", since "v0.3.0", required "v0.14.0";
    // SPEC-6.69: required since v0.4.0.
    /// AES-256-GCM key for at-rest encryption, which a database-backed
    /// provider would need in order to read anything it stored.
    Bootstrap ENCRYPTION_KEY = "ENCRYPTION_KEY", since "v0.1.0", required "v0.4.0";
    // SPEC-6.73: blank means the file secret provider is not built.
    /// PMS-988: directory the file-backed application-tier secret provider
    /// reads. A provider is built from this at boot, so it is bootstrap; unset
    /// means the file provider is not enabled and holds nothing.
    Bootstrap APP_SECRETS_DIR = "APP_SECRETS_DIR", since "v0.14.0", optional;

    // PMS-987: the configuration chain and the two providers whose
    // construction values themselves live under Configuration. Bootstrap
    // because every one of them is what a provider is BUILT FROM (a
    // directory, an API base, a machine credential), and configuration
    // that says where to find configuration cannot live inside what it
    // locates.

    // SPEC-6.87, SPEC-6.19: construction input of the file configuration provider.
    /// Directory the file configuration provider reads, one file per key.
    Bootstrap CONFIG_FILE_DIR = "CONFIG_FILE_DIR", since "v0.14.0", optional;
    /// Comma-separated priority list of enabled configuration providers,
    /// e.g. `file,database,environment`. Empty falls back to the hosting
    /// profile's default. This is provider ENABLEMENT and cannot be
    /// served by any provider it enables.
    Bootstrap CONFIG_PROVIDERS = "CONFIG_PROVIDERS", since "v0.14.0", optional;
    /// Base URL of the Bunyip API the Bunyip configuration provider reads.
    Bootstrap BUNYIP_CONFIG_URL = "BUNYIP_CONFIG_URL", since "v0.14.0", optional;
    /// Machine-credential client id this deployment presents to Bunyip's
    /// `GET /v1/host/config/{KEY}`, as HTTP Basic.
    Bootstrap BUNYIP_CONFIG_CLIENT_ID = "BUNYIP_CONFIG_CLIENT_ID", since "v0.14.0", optional;
    /// Machine-credential client secret for the same HTTP Basic credential.
    Bootstrap BUNYIP_CONFIG_CLIENT_SECRET = "BUNYIP_CONFIG_CLIENT_SECRET", since "v0.14.0", optional;
    // SPEC-6.77: enablement list, resolved once; the profile default stands when blank.
    // SPEC-2.227
    /// PMS-981: authentication provider enablement, a comma-separated priority
    /// list (`bunyip,local` by default in `saas`; `local` in `self-hosted`).
    /// Bootstrap because provider enablement is bootstrap configuration
    /// (PMS-1009): the resolved chain is built once at startup and a change
    /// needs a restart, since the trait objects the chain is made of are
    /// already holding the old shape.
    Bootstrap AUTH_PROVIDERS = "AUTH_PROVIDERS", since "v0.14.0", optional;

    // -- Application: the server's own shape ---------------------------------

    // SPEC-6.52: default "development" only when unset.
    Application ENVIRONMENT = "ENVIRONMENT", since "v0.1.0", optional;
    // SPEC-6.53: defaults 0.0.0.0 and 8080.
    Application HOST = "HOST", since "v0.1.0", optional;
    Application PORT = "PORT", since "v0.1.0", optional;
    // SPEC-6.55: required since v0.14.0.
    Application BASE_URL = "BASE_URL", since "v0.1.0", required "v0.14.0";
    // SPEC-6.54: bool literals true/false only; default true.
    Application RUN_MIGRATIONS = "RUN_MIGRATIONS", since "v0.1.0", optional;
    // SPEC-6.68: JWT_SECRET required since v0.4.0, BUNYIP_WEBHOOK_SECRET required since v0.6.0.
    Application JWT_SECRET = "JWT_SECRET", since "v0.1.0", required "v0.4.0";
    Application BUNYIP_WEBHOOK_SECRET = "BUNYIP_WEBHOOK_SECRET", since "v0.6.0", required;
    // SPEC-6.56: required since v0.14.0.
    Application CLIENT_ORIGIN = "CLIENT_ORIGIN", since "v0.2.0", required "v0.14.0";
    // SPEC-6.58: comma list, wildcard form, panics on a malformed entry.
    Application CORS_ORIGIN = "CORS_ORIGIN", since "v0.2.0", optional;
    // SPEC-6.61
    /// Optional `Domain=` attribute for the contact-portal refresh cookie
    /// (`mokosh:contact_token`). Set to the shared apex (e.g. `.a8n.run`) when
    /// the SPA runs on tenant-*.<apex> and reaches the API host at a different
    /// subdomain, so the cookie reaches `/api/v1/contact/auth/refresh` from
    /// that origin; unset leaves the cookie host-scoped as before.
    Application PORTAL_COOKIE_DOMAIN = "PORTAL_COOKIE_DOMAIN", since "v0.19.0", optional;
    // SPEC-6.57: required since v0.14.0.
    Application SPA_BASE_URL = "SPA_BASE_URL", since "v0.12.0", required "v0.14.0";
    // SPEC-6.59
    Application PUBLIC_API_BASE_URL = "PUBLIC_API_BASE_URL", since "v0.12.0", optional;
    // SPEC-6.60
    Application ABUSE_CONTACT_EMAIL = "ABUSE_CONTACT_EMAIL", since "v0.12.0", optional;
    // SPEC-6.62: positive integer, read once at boot.
    Application MOKOSH_MAX_TENANTS = "MOKOSH_MAX_TENANTS", since "v0.14.0", optional;
    // SPEC-6.63
    Application MOKOSH_UPDATE_CHECK_URL = "MOKOSH_UPDATE_CHECK_URL", since "v0.3.0", optional;

    // -- Mail ----------------------------------------------------------------

    // SPEC-6.90
    /// PMS-1013: named email provider selection. Explicit `log` or `smtp` wins
    /// over the hosting profile's default and over the implicit `SMTP_HOST`
    /// signal; unset falls back to the profile default (self-hosted: `log`,
    /// saas: `smtp`), or to `smtp` when the operator set `SMTP_HOST` but chose
    /// no provider name (backward compat with the pre-PMS-1013 implicit rule).
    /// An unusable `smtp` selection (no host) is a boot error, and an explicit
    /// `log` while `SMTP_HOST` is set warns rather than silently discarding
    /// the operator's relay configuration.
    Application MAIL_PROVIDER = "MAIL_PROVIDER", since "v0.14.0", optional;
    // SPEC-6.91
    Application SMTP_HOST = "SMTP_HOST", since "v0.2.0", optional;
    Application SMTP_PORT = "SMTP_PORT", since "v0.2.0", optional;
    Application SMTP_USERNAME = "SMTP_USERNAME", since "v0.2.0", optional;
    // SPEC-6.76: also a governed application secret.
    Application SMTP_PASSWORD = "SMTP_PASSWORD", since "v0.2.0", optional;
    Application SMTP_FROM = "SMTP_FROM", since "v0.2.0", optional;
    Application SMTP_TLS = "SMTP_TLS", since "v0.2.0", optional;
    // SPEC-6.92
    /// PMS-1482: base URL of Bunyip's mailer relay (`POST /v1/mailer/send`,
    /// BUNYIP-602) that `MAIL_PROVIDER=bunyip` sends through instead of SMTP.
    Application BUNYIP_MAILER_URL = "BUNYIP_MAILER_URL", since "v0.16.0", optional;
    /// Machine-credential client id presented as HTTP Basic to the relay.
    Application BUNYIP_MAILER_CLIENT_ID = "BUNYIP_MAILER_CLIENT_ID", since "v0.16.0", optional;
    /// Machine-credential client secret presented as HTTP Basic to the relay.
    Application BUNYIP_MAILER_CLIENT_SECRET = "BUNYIP_MAILER_CLIENT_SECRET", since "v0.16.0", optional;

    // -- Authentication ------------------------------------------------------

    // SPEC-6.78
    Application OIDC_ISSUER = "OIDC_ISSUER", since "v0.3.0", optional;
    Application OIDC_AUDIENCE = "OIDC_AUDIENCE", since "v0.3.0", optional;
    // SPEC-6.79
    Application OIDC_JWKS_CACHE_TTL_SECS = "OIDC_JWKS_CACHE_TTL_SECS", since "v0.3.0", optional;
    Application OIDC_LEEWAY_SECONDS = "OIDC_LEEWAY_SECONDS", since "v0.3.0", optional;
    // SPEC-6.80
    Application OIDC_DEFAULT_TENANT_ID = "OIDC_DEFAULT_TENANT_ID", since "v0.3.0", optional;
    // PMS-998: the OIDC client id bunyip addresses a back-channel logout
    // token to. NOT OIDC_AUDIENCE, which is the resource-server audience the
    // access token carries: bunyip mints a logout token with `aud =
    // client_id`, so the two are different values and the receiver refuses
    // everything while this is unset.
    // SPEC-6.81
    Application OIDC_BACKCHANNEL_CLIENT_ID = "OIDC_BACKCHANNEL_CLIENT_ID", since "v0.15.0", optional;
    // SPEC-6.82
    Application ADMIN_EMAIL = "ADMIN_EMAIL", since "v0.1.0", optional;
    Application ADMIN_PASSWORD = "ADMIN_PASSWORD", since "v0.1.0", optional;
    // SPEC-6.84: boolean flag, read once at boot.
    Application LOGIN_APPROVAL_ENABLED = "LOGIN_APPROVAL_ENABLED", since "v0.8.0", optional;

    // SPEC-6.83
    /// Opts in to JIT-provisioning a personal tenant for a first-sight
    /// bunyip identity whose email the OP has verified. Off by default so
    /// production stays invitation-only; staging turns it on explicitly.
    /// Verified-email is a hard requirement at the gate; this flag never
    /// relaxes it.
    Application ALLOW_UNINVITED_BUNYIP_SIGNUP = "ALLOW_UNINVITED_BUNYIP_SIGNUP", since "v0.16.0", optional;

    // SPEC-6.86
    /// PMS-1193 / BUNYIP-641: the Bunyip machine-credential client_id this
    /// deployment accepts on the admin provider-status routes. Set together
    /// with `BUNYIP_STATUS_CLIENT_SECRET`; when either is unset the machine-
    /// credential path is disabled and the routes gate on `RequireAdmin`
    /// alone (the pre-PMS-1193 behaviour). Presented by Bunyip as HTTP
    /// Basic per `bunyip/docs/provider-status-contract.md`.
    Application BUNYIP_STATUS_CLIENT_ID = "BUNYIP_STATUS_CLIENT_ID", since "v0.14.0", optional;
    /// PMS-1193 / BUNYIP-641: the plaintext client_secret paired with
    /// `BUNYIP_STATUS_CLIENT_ID`. Compared in constant time against the
    /// Basic auth Bunyip presents. Unset disables the machine-credential
    /// path; a set value stays in the operator's SOPS-encrypted
    /// compose-secrets on staging and prod.
    Application BUNYIP_STATUS_CLIENT_SECRET = "BUNYIP_STATUS_CLIENT_SECRET", since "v0.14.0", optional;

    // SPEC-6.85
    /// PMS-1208: base URL of the Bunyip API this deployment federates with in
    /// SaaS mode. Used by [`crate::modules::auth::bunyip_directory`] to call
    /// `GET /v1/users/lookup?email=` before creating a pending grant
    /// invitation. Unset in standalone mode; the directory client is only
    /// constructed when this + the machine-credential pair below are all set.
    Application BUNYIP_API_BASE_URL = "BUNYIP_API_BASE_URL", since "v0.16.0", optional;
    /// PMS-1208: machine-credential client_id this deployment presents to
    /// Bunyip's `/v1/users/lookup` endpoint. Same shape as
    /// `BUNYIP_STATUS_CLIENT_ID` above, but for the outbound direction:
    /// Bunyip is the server, mokosh-server is the calling app. Register
    /// via `bunyip-api machine-client register` on the Bunyip side.
    Application BUNYIP_DIRECTORY_CLIENT_ID = "BUNYIP_DIRECTORY_CLIENT_ID", since "v0.16.0", optional;
    /// PMS-1208: plaintext client_secret paired with
    /// `BUNYIP_DIRECTORY_CLIENT_ID`. Presented to Bunyip as HTTP Basic.
    /// Stored in the operator's SOPS-encrypted compose secrets on staging
    /// and prod; unset in standalone mode.
    Application BUNYIP_DIRECTORY_CLIENT_SECRET = "BUNYIP_DIRECTORY_CLIENT_SECRET", since "v0.16.0", optional;


    // -- Feature flags (PMS-983) ---------------------------------------------
    // Reached through `crate::config::flags`, so the parse rule and the
    // default live with the flag rather than at every read site. No feature
    // annotation: an unset key is the flag's default and the boot log stays
    // silent, matching the registry convention.

    // SPEC-6.31: declared flag with no reader outside src/config.
    /// PMS-983: the organizations feature. Read through
    /// `crate::config::flags::ORGANIZATIONS_ENABLED`, which defaults per
    /// hosting profile (off on self-hosted, on for SaaS).
    Application ORGANIZATIONS_ENABLED = "ORGANIZATIONS_ENABLED", since "v0.14.0", optional;
    // SPEC-6.99, SPEC-6.100
    Application IP2LOCATION_DB_PATH = "IP2LOCATION_DB_PATH", since "v0.7.0", optional;
    Application IP2PROXY_DB_PATH = "IP2PROXY_DB_PATH", since "v0.11.0", optional;

    // -- Network ------------------------------------------------------------

    // SPEC-6.101
    Application TRUSTED_PROXY_CIDR = "TRUSTED_PROXY_CIDR", since "v0.7.0", optional;
    // SPEC-6.102
    Application OUTBOUND_PRIVATE_ALLOWLIST = "OUTBOUND_PRIVATE_ALLOWLIST", since "v0.14.0", optional;
    // SPEC-6.75
    /// The in-network Infisical base the readiness probe reports on. Blank
    /// means unconfigured (PMS-707), never a failing probe. The Infisical
    /// SECRET provider reads its own copy at its entry point, because a
    /// provider cannot be built out of values served by itself.
    Application INFISICAL_ADDRESS = "INFISICAL_ADDRESS", since "v0.12.0", optional;

    // -- Payment provider hosts ----------------------------------------------
    // Overridable so an integration test can point the calls at a stub.

    // SPEC-6.103
    Application STRIPE_API_BASE = "STRIPE_API_BASE", since "v0.10.0", optional;
    Application PAYPAL_API_BASE = "PAYPAL_API_BASE", since "v0.14.0", optional;

    // -- Uploads -------------------------------------------------------------
    // The storage ROOT is not declared here. It is `STORAGE_ROOT` (PMS-1317),
    // read by `crate::storage::env` at the provider of record's entry point
    // along with the rest of the `STORAGE_*` settings and its deprecated
    // `ATTACHMENT_DIR` alias, the same way `STORAGE_PROVIDER` and the
    // `STORAGE_S3_*` block are. Branding used to declare it here and read it a
    // second time; it now asks `crate::storage`, so there is one reader again.

    // SPEC-6.96, SPEC-6.98: caps parse as positive integers; a bad value is a configuration error.
    Application ATTACHMENT_MAX_BYTES = "ATTACHMENT_MAX_BYTES", since "v0.4.0", optional;
    Application KB_ATTACHMENT_MAX_BYTES = "KB_ATTACHMENT_MAX_BYTES", since "v0.14.0", optional;

    // The six `BrandingAssetStore::max_bytes` caps. They are a closed match on
    // `(AssetScope, BrandAssetKind)`, which is why all six are declarable and
    // why a literal-only scan of the read site saw none of them.
    // SPEC-6.97
    Application TENANT_LOGO_MAX_BYTES = "TENANT_LOGO_MAX_BYTES", since "v0.12.0", optional;
    Application BRANDING_TENANT_FAVICON_MAX_BYTES = "BRANDING_TENANT_FAVICON_MAX_BYTES", since "v0.14.0", optional;
    Application BRANDING_TENANT_BACKGROUND_MAX_BYTES = "BRANDING_TENANT_BACKGROUND_MAX_BYTES", since "v0.14.0", optional;
    Application BRANDING_COMPANY_LOGO_MAX_BYTES = "BRANDING_COMPANY_LOGO_MAX_BYTES", since "v0.14.0", optional;
    Application BRANDING_COMPANY_FAVICON_MAX_BYTES = "BRANDING_COMPANY_FAVICON_MAX_BYTES", since "v0.14.0", optional;
    Application BRANDING_COMPANY_BACKGROUND_MAX_BYTES = "BRANDING_COMPANY_BACKGROUND_MAX_BYTES", since "v0.14.0", optional;

    // -- Seeding -------------------------------------------------------------

    // SPEC-6.88, SPEC-6.89
    Application MOKOSH_SEED_TENANT_ID = "MOKOSH_SEED_TENANT_ID", since "v0.3.0", optional;
    Application MOKOSH_DEMO_SEED = "MOKOSH_DEMO_SEED", since "v0.3.0", optional;
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

    fn version(v: &str) -> (u32, u32, u32) {
        let parts: Vec<u32> = v
            .strip_prefix('v')
            .unwrap_or_else(|| panic!("{v} must start with v"))
            .split('.')
            .map(|p| p.parse().unwrap_or_else(|_| panic!("{v} is not vX.Y.Z")))
            .collect();
        assert_eq!(parts.len(), 3, "{v} is not vX.Y.Z");
        (parts[0], parts[1], parts[2])
    }

    /// PMS-1442: the "Added in" column is rendered from `since`, so a malformed
    /// one would print a release that never existed.
    #[test]
    fn every_key_names_the_release_that_added_it() {
        for key in REGISTRY {
            let since = version(key.since());
            if let Some(later) = key.required_since() {
                assert!(key.required(), "{key}: required_since on an optional key");
                assert!(
                    version(later) > since,
                    "{key}: required_since must come after since"
                );
            }
        }
    }

    /// PMS-1442: `required` means boot refuses the key outside dev/test
    /// (`resolve_secret`, PMS-1160's essential list, the database URL).
    #[test]
    fn the_required_keys_are_the_ones_boot_refuses_without() {
        let required: Vec<&str> = REGISTRY
            .iter()
            .filter(|k| k.required())
            .map(|k| k.name())
            .collect();
        assert_eq!(
            required,
            [
                "DATABASE_URL",
                "MOKOSH_APP_DATABASE_URL",
                "ENCRYPTION_KEY",
                "BASE_URL",
                "JWT_SECRET",
                "BUNYIP_WEBHOOK_SECRET",
                "CLIENT_ORIGIN",
                "SPA_BASE_URL",
            ],
            "a key that boot now refuses without needs `required` in its \
             declaration and a won't-start entry in docs/configuration.md"
        );
    }

    /// The bootstrap tier is small and stated, because every key in it either
    /// names a value a later provider cannot serve (the three connection- and
    /// encryption-material keys) or names PROVIDER ENABLEMENT itself, which
    /// resolves once at startup because a chain of trait objects is already
    /// holding the shape it decided. Growing it silently is how the tier
    /// stops meaning "resolves exactly once per process".
    #[test]
    fn the_bootstrap_tier_is_exactly_what_a_provider_is_made_from() {
        let bootstrap: Vec<&str> = REGISTRY
            .iter()
            .filter(|k| k.tier() == Tier::Bootstrap)
            .map(|k| k.name())
            .collect();
        assert_eq!(
            bootstrap,
            [
                "DATABASE_URL",
                "MOKOSH_APP_DATABASE_URL",
                "ENCRYPTION_KEY",
                "APP_SECRETS_DIR",
                "CONFIG_FILE_DIR",
                "CONFIG_PROVIDERS",
                "BUNYIP_CONFIG_URL",
                "BUNYIP_CONFIG_CLIENT_ID",
                "BUNYIP_CONFIG_CLIENT_SECRET",
                "AUTH_PROVIDERS",
            ],
            "adding a bootstrap key means arguing that a provider cannot serve \
             it, or that the value chooses which providers run and so must not \
             change under the running chain"
        );
    }
}
