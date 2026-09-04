//! PMS-967: where a tenant's secret lives, decided once.
//!
//! Every tenant-supplied secret today is AES-256-GCM ciphertext in a column on
//! the feature's own table. `payment_gateway_configs.config_encrypted` is the
//! one that matters: encrypted with the host `ENCRYPTION_KEY`, decrypted
//! strictly server-side, never returned to a client (PMS-342). That works. What
//! it does not do is let an operator decide WHERE the secret lives, and PMS-912
//! asks for MSP-supplied integration credentials to be in Infisical. With a
//! per-feature column the only way there is to teach each feature about
//! Infisical separately.
//!
//! So this is the same shape [`crate::storage`] took for files (PMS-910): a
//! trait, a key a caller cannot forge a path out of, the existing behaviour as
//! the default provider, and a second provider selected by configuration that
//! no caller can distinguish. Local storage stayed the default there and the
//! database stays the default here, for the same reason: self-hosting must not
//! acquire a dependency to keep working.
//!
//! PMS-1010 settled the word: a selectable implementation of a capability is a
//! PROVIDER, here as in [`crate::storage`] and as
//! [`crate::modules::billing::provider::PaymentProvider`] already was. The
//! operator-facing variable is still `SECRET_BACKEND` and deliberately so:
//! renaming it breaks every existing deployment for a vocabulary change.
//!
//! Nothing calls this yet. PMS-968 moves the payment-gateway credentials over.
//!
//! # What a provider outage means
//!
//! This is the decision PMS-967 exists to make rather than discover later, and
//! it is stated here because the answer is not obvious.
//!
//! The database provider fails when Postgres fails, which is the whole
//! application failing, so it raises no new question. Infisical is different:
//! it is optional today at every layer (`/ready` reports `"skipped"` when
//! `INFISICAL_ADDRESS` is blank, and it sits behind a compose profile in dev),
//! and putting credentials in it gives the features that read them a hard
//! runtime dependency on a service whose absence is currently tolerated.
//!
//! The sharp edge is the pre-auth payment webhook. It fetches the very secret
//! it needs to verify an inbound signature, before anything about the request
//! is trusted. If that fetch is a network call and Infisical is unreachable,
//! every payment webhook fails at once.
//!
//! The answer taken here is a read-through cache with a TTL, and a hard failure
//! on a miss. Three reasons, in order of weight. A secret changes when an
//! operator reconnects an integration, which is rare, so a cache is nearly
//! always warm and an outage is invisible to a running deployment. A payment
//! provider retries a failed webhook with backoff for days, so a cold miss
//! during an outage is a delay and not a lost payment. And failing is honest:
//! the alternative, falling back to a stale or database copy, means the
//! deployment quietly stops using the provider the operator chose, which is the
//! kind of silent degrade PMS-289 and PMS-905 both came from.
//!
//! The cost is stated plainly: the cache holds plaintext secrets in process
//! memory for its TTL. They are already in memory transiently on every use, and
//! the TTL bounds how long. An operator who will not accept that keeps the
//! database provider, which is the default.

use std::fmt;

use async_trait::async_trait;
use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};

pub mod database;
pub mod infisical;

pub use database::DatabaseSecretProvider;
pub use infisical::InfisicalSecretProvider;

/// What a stored secret belongs to.
///
/// One variant per kind of secret, the way [`crate::storage::ObjectKind`] has
/// one per kind of stored file. A kind carries whatever identifies the secret
/// WITHIN its tenant and never the tenant itself: that lives on the key, so no
/// arm can forget it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretKind {
    /// A tenant's payment-provider credentials, keyed by the discriminator
    /// stored in `payment_gateway_configs.provider` (PMS-966).
    PaymentGateway { provider: String },
}

impl SecretKind {
    /// The kind's own segment of the name.
    fn prefix(&self) -> &'static str {
        match self {
            SecretKind::PaymentGateway { .. } => "PAYMENT_GATEWAY",
        }
    }

    /// The discriminator within the kind.
    fn discriminator(&self) -> &str {
        match self {
            SecretKind::PaymentGateway { provider } => provider,
        }
    }
}

/// A tenant plus the thing the secret belongs to.
///
/// Constructed only through the named constructors, so a caller cannot build
/// one out of a string it received. The tenant is not optional and is not part
/// of any [`SecretKind`], which is what makes "this key names another tenant's
/// secret" unrepresentable rather than merely unlikely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey {
    tenant_id: Uuid,
    kind: SecretKind,
}

impl SecretKey {
    pub fn payment_gateway(tenant_id: Uuid, provider: impl Into<String>) -> Self {
        Self {
            tenant_id,
            kind: SecretKind::PaymentGateway {
                provider: provider.into(),
            },
        }
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn kind(&self) -> &SecretKind {
        &self.kind
    }

    /// The secret's stable identity: `KIND__<tenant>__<DISCRIMINATOR>`.
    ///
    /// One name serves both providers, as the `secrets.name` column and as the
    /// Infisical secret name, so a deployment that switches providers is
    /// addressing the same secrets rather than a parallel set.
    ///
    /// The tenant is in the name even though the database provider also filters
    /// on `tenant_id` and RLS confines the read. Infisical has no equivalent of
    /// either, so without it every tenant's gateway credentials would collide
    /// on one name in one folder, and the first write would overwrite the rest.
    ///
    /// Hyphens are dropped from the uuid and the discriminator is uppercased
    /// because an Infisical secret name is conventionally `A-Z0-9_`.
    pub fn name(&self) -> AppResult<String> {
        let discriminator = self.kind.discriminator();
        validate_discriminator(discriminator)?;
        Ok(format!(
            "{}__{}__{}",
            self.kind.prefix(),
            self.tenant_id.simple(),
            discriminator.to_ascii_uppercase()
        ))
    }
}

impl fmt::Display for SecretKey {
    /// Names the key, never the value. Safe to log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.kind.prefix(),
            self.tenant_id,
            self.kind.discriminator()
        )
    }
}

/// A discriminator has to survive being a path segment and a secret name in a
/// system this code does not control, so the accepted set is small and stated
/// rather than inherited from whatever the caller had.
///
/// This is the check that stops a crafted `provider` value from walking out of
/// its folder or colliding with another key's name. It is not defence against
/// the operator: `provider` is already constrained to an enum on the way in
/// (PMS-966). It is defence against the next caller, who will pass something
/// else.
fn validate_discriminator(value: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > 40 {
        return Err(AppError::Configuration(format!(
            "secret discriminator {value:?} must be 1 to 40 characters"
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(AppError::Configuration(format!(
            "secret discriminator {value:?} must be lowercase ASCII, digits or underscore"
        )));
    }
    Ok(())
}

/// What a feature can ask of the secret provider.
///
/// Deliberately small, and deliberately without a method that takes a name:
/// everything is addressed by [`SecretKey`], so there is no call that can reach
/// a secret belonging to another tenant.
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// The stored value, or `None` when nothing is stored for this key.
    ///
    /// A missing secret is `None` and not an error, because "this tenant has
    /// not configured the integration" is the ordinary case and every caller
    /// has to handle it anyway. A provider that is unreachable IS an error, and
    /// the two must never collapse into each other: treating an outage as "not
    /// configured" is how a payment integration silently turns itself off.
    async fn get(&self, key: &SecretKey) -> AppResult<Option<String>>;

    /// Store a value, replacing whatever was there.
    async fn put(&self, key: &SecretKey, value: &str) -> AppResult<()>;

    /// Best-effort: a secret that is already gone is not an error, matching
    /// [`crate::storage::ObjectProvider::delete`] and for the same reason - the
    /// caller has already removed the row that pointed at it.
    async fn delete(&self, key: &SecretKey) -> AppResult<()>;
}

/// Which provider holds secrets for this deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretProviderKind {
    /// The `secrets` table, AES-256-GCM under the host `ENCRYPTION_KEY`. The
    /// default, so a deployment that configures nothing keeps working.
    Database,
    /// Infisical, via the Universal Auth machine identity the bootstrap
    /// provisions.
    Infisical,
}

impl SecretProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretProviderKind::Database => "database",
            SecretProviderKind::Infisical => "infisical",
        }
    }
}

/// Provider selection.
#[derive(Clone, Copy, Debug)]
pub struct SecretsConfig {
    pub provider: SecretProviderKind,
}

impl SecretsConfig {
    /// The ONE reader of `SECRET_BACKEND`, the way
    /// [`crate::storage::StorageConfig::from_env`] is the only reader of
    /// `ATTACHMENT_DIR`. A second reader is how two parts of one process come
    /// to disagree about where secrets are.
    ///
    /// An unset or blank value is `Database`, because a forwarded-but-unset
    /// variable arrives as `""` (PMS-836) and the default has to be the one
    /// that needs no other service. An unrecognised value is a hard error
    /// rather than a fallback to the default: an operator who wrote
    /// `SECRET_BACKEND=infisical ` with a typo asked for Infisical, and quietly
    /// giving them the database is the silent degrade this module refuses
    /// everywhere else.
    pub fn from_env() -> AppResult<Self> {
        Self::parse(&std::env::var("SECRET_BACKEND").unwrap_or_default())
    }

    /// The rule itself, split out so it can be tested without writing to
    /// process-global env under a concurrent test runner.
    pub fn parse(raw: &str) -> AppResult<Self> {
        let provider = match raw.trim() {
            "" | "database" => SecretProviderKind::Database,
            "infisical" => SecretProviderKind::Infisical,
            other => {
                return Err(AppError::Configuration(format!(
                    "SECRET_BACKEND {other:?} is not a known provider; expected 'database' or 'infisical'"
                )))
            }
        };
        Ok(Self { provider })
    }
}

/// Build the provider this deployment is configured for.
///
/// The ONE place a [`SecretProviderKind`] becomes a [`SecretProvider`], so no
/// construction site can pick a provider of its own. It is fallible and sync on
/// purpose: callers build it once at startup where a `Result` can end the
/// process, which is what makes "a half-configured deployment fails at boot
/// rather than when a customer tries to pay" true rather than aspirational.
pub fn provider_from_env(
    db: crate::db::Database,
    encryption_key: [u8; 32],
) -> AppResult<std::sync::Arc<dyn SecretProvider>> {
    let config = SecretsConfig::from_env()?;
    let provider: std::sync::Arc<dyn SecretProvider> = match config.provider {
        SecretProviderKind::Database => {
            std::sync::Arc::new(DatabaseSecretProvider::new(db, encryption_key))
        }
        SecretProviderKind::Infisical => std::sync::Arc::new(InfisicalSecretProvider::from_env()?),
    };
    tracing::info!(
        provider = config.provider.as_str(),
        "secret provider selected"
    );
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: Uuid = Uuid::from_u128(1);
    const OTHER: Uuid = Uuid::from_u128(2);

    /// The property the whole key type exists for. Infisical is a flat
    /// namespace with no tenant filter and no RLS, so if two tenants' keys can
    /// produce one name, the second write silently replaces the first tenant's
    /// credentials.
    #[test]
    fn two_tenants_cannot_address_the_same_secret() {
        let mine = SecretKey::payment_gateway(TENANT, "stripe");
        let theirs = SecretKey::payment_gateway(OTHER, "stripe");
        assert_ne!(
            mine.name().unwrap(),
            theirs.name().unwrap(),
            "the same integration in two tenants must not share a name"
        );
    }

    /// The name is the row's identity in one provider and the secret's identity
    /// in the other, so it is pinned rather than left to drift: changing it
    /// orphans every secret already written under the old one.
    #[test]
    fn the_name_is_exactly_this_shape() {
        let key = SecretKey::payment_gateway(TENANT, "stripe");
        assert_eq!(
            key.name().unwrap(),
            "PAYMENT_GATEWAY__00000000000000000000000000000001__STRIPE"
        );
    }

    /// A crafted discriminator must not walk out of its folder or collide with
    /// another key's name. `provider` is enum-constrained on the way in today,
    /// so this guards the next caller rather than the current one.
    #[test]
    fn a_discriminator_cannot_escape_its_own_segment() {
        for hostile in [
            "../other",
            "stripe/../../etc",
            "stripe secret",
            "STRIPE",
            "stripe-live",
            "",
        ] {
            let key = SecretKey::payment_gateway(TENANT, hostile);
            assert!(
                key.name().is_err(),
                "{hostile:?} must be refused as a discriminator"
            );
        }
        assert!(SecretKey::payment_gateway(TENANT, "authorize_net")
            .name()
            .is_ok());
    }

    /// Displaying a key must never be a way to log a secret.
    #[test]
    fn displaying_a_key_names_it_and_nothing_else() {
        let shown = SecretKey::payment_gateway(TENANT, "stripe").to_string();
        assert!(shown.contains("stripe"));
        assert!(shown.contains(&TENANT.to_string()));
    }

    /// Unset and blank both mean the default, because a forwarded-but-unset
    /// compose variable arrives as an empty string (PMS-836).
    #[test]
    fn an_unset_provider_is_the_database() {
        for raw in ["", "   ", "database"] {
            assert_eq!(
                SecretsConfig::parse(raw).unwrap().provider,
                SecretProviderKind::Database
            );
        }
        assert_eq!(
            SecretsConfig::parse("infisical").unwrap().provider,
            SecretProviderKind::Infisical
        );
    }

    /// A typo asked for something. Answering with the default would mean an
    /// operator who wrote `infisicial` keeps storing secrets in Postgres and is
    /// never told.
    #[test]
    fn an_unrecognised_provider_is_refused_and_not_defaulted() {
        for raw in ["infisicial", "vault", "DATABASE", "none"] {
            assert!(
                SecretsConfig::parse(raw).is_err(),
                "{raw:?} must not silently become the default"
            );
        }
    }

    /// One reader of the selection variable, the way
    /// `storage::tests::there_is_one_default_root` pins one reader of
    /// `ATTACHMENT_DIR`. Two readers is how two parts of one process come to
    /// disagree about where secrets are.
    #[test]
    fn there_is_one_reader_of_the_provider_setting() {
        const SRC: &str = include_str!("mod.rs");
        assert_eq!(
            SRC.matches(concat!("var(\"SECRET", "_BACKEND\")")).count(),
            1,
            "SECRET_BACKEND is read in exactly one place"
        );
    }
}
