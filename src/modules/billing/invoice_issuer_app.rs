//! MAPPS-1139: the host's Xero and QuickBooks OAuth applications.
//!
//! Which Xero application this Mokosh installation authenticates as is a
//! property of the deployment, not of a tenant. That is PMS-1430's
//! conclusion for Google and MAPPS-1101's for Microsoft 365, and the
//! reasoning transfers without modification: a tenant-owned client costs
//! the tenant a developer-console walkthrough before they can issue a
//! single invoice, an application left unverified is capped and warned
//! about, and competing products ship one vendor-owned verified
//! application that the MSP connects to by pressing a button.
//!
//! MAPPS-1099's credential blob did the opposite, holding a `client_id`
//! and `client_secret` per tenant. Nothing had been deployed on it: the
//! feature flag defaults off everywhere, no tenant holds a blob, and
//! `ProviderBuild::Planned` keeps both providers off every surface. So the
//! shape changed here rather than after the first MSP had pasted a client
//! secret into a form.
//!
//! Both halves of a pair are governed secrets, never an id in
//! configuration beside a governed secret, for PMS-1430's stated reason:
//! they would resolve from different providers and a mismatched pair fails
//! at the provider with an error nobody can place. A half-configured host
//! is a boot error naming the missing key, because there is no next rung to
//! fall to.

use crate::app_secrets::{AppSecrets, GovernedSecret};
use crate::modules::billing::invoice_issuer::InvoiceProviderKind;
use crate::utils::error::{AppError, AppResult};

/// One provider's application, as this deployment holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerApp {
    pub client_id: String,
    pub client_secret: String,
    /// The key the provider signs webhook deliveries with, when the
    /// deployment has subscribed. `None` is a deployment that connects and
    /// issues but is never told what happened afterwards, which is a
    /// degraded state worth running rather than refusing to boot over.
    pub webhook_key: Option<String>,
}

/// Both applications, resolved once at boot.
#[derive(Debug, Clone, Default)]
pub struct IssuerApps {
    pub xero: Option<IssuerApp>,
    pub quickbooks: Option<IssuerApp>,
}

impl IssuerApps {
    /// Read both pairs through the application-tier secret seam.
    ///
    /// Three outcomes per provider, and the third is why this returns a
    /// `Result`. Both halves present is a configured host. Neither is an
    /// unconfigured one, which the Settings card renders as "not available
    /// on this deployment" rather than as a Connect button that cannot
    /// work. One half without the other is neither: it is a host that would
    /// connect as half an application, so it is an error naming the key
    /// that is missing, raised at boot where an operator is present to read
    /// it rather than at a customer's first click.
    pub fn from_app_secrets(secrets: &AppSecrets) -> AppResult<Self> {
        Ok(Self {
            xero: resolve(
                secrets,
                InvoiceProviderKind::Xero,
                GovernedSecret::XeroClientId,
                GovernedSecret::XeroClientSecret,
                GovernedSecret::XeroWebhookKey,
            )?,
            quickbooks: resolve(
                secrets,
                InvoiceProviderKind::Quickbooks,
                GovernedSecret::QuickbooksClientId,
                GovernedSecret::QuickbooksClientSecret,
                GovernedSecret::QuickbooksVerifierToken,
            )?,
        })
    }

    pub fn get(&self, provider: InvoiceProviderKind) -> Option<&IssuerApp> {
        match provider {
            InvoiceProviderKind::Xero => self.xero.as_ref(),
            InvoiceProviderKind::Quickbooks => self.quickbooks.as_ref(),
        }
    }

    /// The application, or the refusal an operator can act on.
    ///
    /// Named as a conflict rather than an internal error: the deployment is
    /// working as configured and what is missing is configuration, which is
    /// a different thing from a bug and reads differently to whoever sees
    /// it.
    pub fn require(&self, provider: InvoiceProviderKind) -> AppResult<&IssuerApp> {
        self.get(provider).ok_or_else(|| {
            AppError::Conflict(format!(
                "{} invoicing is not available on this deployment: no {} application is \
                 configured for it.",
                provider.as_str(),
                provider.as_str()
            ))
        })
    }
}

fn resolve(
    secrets: &AppSecrets,
    provider: InvoiceProviderKind,
    id: GovernedSecret,
    secret: GovernedSecret,
    webhook: GovernedSecret,
) -> AppResult<Option<IssuerApp>> {
    let read = |which: GovernedSecret| {
        secrets
            .get(which)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    match (read(id), read(secret)) {
        (Some(client_id), Some(client_secret)) => Ok(Some(IssuerApp {
            client_id,
            client_secret,
            webhook_key: read(webhook),
        })),
        (None, None) => Ok(None),
        (Some(_), None) => Err(half_configured(provider, id, secret)),
        (None, Some(_)) => Err(half_configured(provider, secret, id)),
    }
}

/// The boot error for a host holding one half of a pair.
///
/// Names the MISSING key rather than the present one, because the
/// operator's next action is to add it, and says where it goes without
/// naming a provider: which provider serves it is `SECRET_BACKEND`'s answer
/// and the app-secret survey already logs it.
fn half_configured(
    provider: InvoiceProviderKind,
    present: GovernedSecret,
    missing: GovernedSecret,
) -> AppError {
    AppError::Configuration(format!(
        "{} invoicing is half configured: {present} is set and {missing} is not. A client id and \
         its secret have to come from the same application and the same provider, so add \
         {missing} beside it or remove both.",
        provider.as_str()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_secrets::AppSecretProvider;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct Fake(HashMap<&'static str, &'static str>);

    #[async_trait::async_trait]
    impl AppSecretProvider for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn get(&self, secret: GovernedSecret) -> Option<String> {
            self.0.get(secret.name()).map(|v| v.to_string())
        }
    }

    fn secrets(pairs: &[(&'static str, &'static str)]) -> AppSecrets {
        AppSecrets::with_provider(
            crate::app_secrets::AppSecretProviderKind::Database,
            Arc::new(Fake(pairs.iter().copied().collect())),
        )
    }

    /// The three outcomes PMS-1430 names, per provider.
    #[test]
    fn a_pair_is_configured_absent_or_an_error_and_never_half_a_client() {
        let none = IssuerApps::from_app_secrets(&secrets(&[])).expect("no pair is not an error");
        assert!(none.xero.is_none() && none.quickbooks.is_none());

        let both = IssuerApps::from_app_secrets(&secrets(&[
            ("XERO_CLIENT_ID", "id"),
            ("XERO_CLIENT_SECRET", "secret"),
        ]))
        .expect("a whole pair");
        assert_eq!(both.xero.as_ref().map(|a| a.client_id.as_str()), Some("id"));
        assert!(
            both.xero
                .as_ref()
                .and_then(|a| a.webhook_key.as_ref())
                .is_none(),
            "a deployment can connect without subscribing to webhooks"
        );
        assert!(
            both.quickbooks.is_none(),
            "one provider configured says nothing about the other"
        );

        let err = IssuerApps::from_app_secrets(&secrets(&[("XERO_CLIENT_ID", "id")]))
            .expect_err("half a client is an error");
        let message = err.to_string();
        assert!(
            message.contains("XERO_CLIENT_SECRET"),
            "the error names what is MISSING, because adding it is the next action: {message}"
        );
    }

    /// A webhook key with no application is not an application.
    ///
    /// The key alone cannot connect anything, and treating it as a half
    /// pair would refuse the boot over a secret that is useless either way.
    #[test]
    fn a_webhook_key_alone_configures_nothing() {
        let apps = IssuerApps::from_app_secrets(&secrets(&[("XERO_WEBHOOK_KEY", "k")]))
            .expect("not a half-configured pair");
        assert!(apps.xero.is_none());
    }

    /// The refusal an operator reads when a tenant tries to use a provider
    /// this deployment has no application for.
    #[test]
    fn requiring_an_unconfigured_provider_says_so_in_the_deployments_terms() {
        let apps = IssuerApps::default();
        let err = apps
            .require(InvoiceProviderKind::Quickbooks)
            .expect_err("nothing is configured");
        assert!(
            err.to_string().contains("not available on this deployment"),
            "{err}"
        );
    }
}
