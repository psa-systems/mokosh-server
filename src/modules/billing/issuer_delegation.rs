//! Declares `ExternalInvoicingProvider` (the enum) and `ExternalIssuer`
//! (the trait) for delegating invoice issuance to an external provider.
//!
//! `integrations/registry.rs` reads `ExternalInvoicingProvider` today to
//! validate a tenant's configured invoicing provider. See
//! `docs/invariants/billing.md#delegated-issuing` for the shipped
//! delegated-issuing behaviour; this file does not describe it.

use crate::utils::error::{AppError, AppResult};

/// The external provider for one tenant's Invoicing delegation.
///
/// `Xero` and `Quickbooks` are the two providers whose registry entries
/// support `Capability::Invoicing`. Stripe is in the registry too but
/// never for invoicing (its invoicing capability is "pay-now links on
/// Mokosh-issued invoices", which is already how `Capability::Payments`
/// works today).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalInvoicingProvider {
    Xero,
    Quickbooks,
}

impl ExternalInvoicingProvider {
    /// The string form stored in `invoices.external_provider`, matching
    /// `IntegrationProvider::as_str` for the same variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xero => "xero",
            Self::Quickbooks => "quickbooks",
        }
    }

    /// Parse a stored discriminator back. Only the two providers this
    /// trait receives are legal; anything else is `None`, because a row
    /// naming something this build cannot drive is a row nothing can
    /// fetch an issuer for.
    ///
    /// Not `std::str::FromStr`: that would make `"stripe".parse()` return
    /// an error rather than `None`, and the caller sites just want to
    /// branch on "a provider this issuer handles" versus "something else"
    /// without carrying an error through.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "xero" => Some(Self::Xero),
            "quickbooks" => Some(Self::Quickbooks),
            _ => None,
        }
    }
}

/// The subset of an issuance request a provider needs to render the
/// invoice document. No implementation of [`ExternalIssuer`] exists, so
/// this shape has never been exercised against a real client; the only
/// impl below, [`NotImplementedIssuer`], never reads these fields.
///
/// Shape is deliberately a struct (versus a trait method with 20
/// parameters) so adding a field later does not break the trait
/// signature.
#[derive(Debug, Clone)]
pub struct IssuanceRequest {
    /// Mokosh's own invoice id, so a webhook update from the provider
    /// can find the local mirror row.
    pub local_invoice_id: uuid::Uuid,
    /// The company this invoice bills. An [`ExternalIssuer`] impl would
    /// resolve this to its own provider-specific contact id (Xero's
    /// Contact GUID, QuickBooks's Customer id); nothing in the repo does
    /// that today.
    pub company_id: uuid::Uuid,
    /// The invoice's total in minor units (cents) and currency, so the
    /// provider's shape is built from the authoritative local value
    /// rather than re-derived from lines.
    pub total_minor: i64,
    pub currency: String,
}

/// What a successful external issuance returns, written onto the local
/// row via the migration 278 columns.
#[derive(Debug, Clone)]
pub struct IssuanceOutcome {
    pub external_invoice_id: String,
    pub external_number: String,
}

/// The trait every external invoicing provider implements. Mokosh's own
/// path does NOT implement this trait: the local flow stays as it is in
/// `billing::service::create_invoice` and the trait is reached only when
/// a tenant has delegated.
#[async_trait::async_trait]
pub trait ExternalIssuer: Send + Sync {
    /// The provider this issuer serves.
    fn provider(&self) -> ExternalInvoicingProvider;

    /// Issue the invoice at the external provider and return what the
    /// local mirror row needs. [`NotImplementedIssuer`] is the only impl
    /// in the repo and always refuses.
    async fn issue(&self, request: &IssuanceRequest) -> AppResult<IssuanceOutcome>;
}

/// Nothing in the repo builds one of these from live data; it has no
/// caller outside its own tests below. If something ever resolves a
/// tenant's delegated providers from the integrations rows, that caller
/// decides which providers count as delegated, and this struct does only
/// the arithmetic over the set it is handed.
///
/// The dispatch's refusal shape is intentional: zero delegations means
/// the local path serves, exactly one means the single delegated provider
/// serves, more than one means a 409 at the API with the offending
/// provider names. A tenant cannot sanely delegate the same job to two
/// systems and expect one invoice.
#[derive(Debug, Default)]
pub struct DelegationDispatch {
    delegated: Vec<ExternalInvoicingProvider>,
}

impl DelegationDispatch {
    /// A dispatch with no delegations: the caller uses the local path.
    pub fn local_only() -> Self {
        Self::default()
    }

    /// A dispatch with the delegations the caller already resolved from
    /// the integrations rows. Nothing in the repo calls this today; the
    /// dispatch's job is just the arithmetic over the resolved set.
    pub fn with(delegated: Vec<ExternalInvoicingProvider>) -> Self {
        Self { delegated }
    }

    /// Which provider the next issuance picks, or `Err(..)` naming the
    /// disagreement. `None` means the local path is chosen (the current
    /// system of record is Mokosh, which is also the Phase 0 default).
    pub fn resolve(&self) -> AppResult<Option<ExternalInvoicingProvider>> {
        match self.delegated.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            many => {
                let names: Vec<&str> = many.iter().map(|p| p.as_str()).collect();
                Err(AppError::Conflict(format!(
                    "Invoicing is delegated to more than one provider ({}). Pick one under \
                     Settings > Integrations before issuing invoices.",
                    names.join(", ")
                )))
            }
        }
    }
}

/// The only impl of [`ExternalIssuer`] in the repo, for every variant of
/// [`ExternalInvoicingProvider`]. The shipped Xero and QuickBooks clients
/// (`provider_invoice::xero`, `provider_invoice::quickbooks`) issue
/// invoices through a different path and never implement this trait, so
/// nothing currently replaces this with a real issuer. Named so a stray
/// grep for the type lands here instead of a stale file.
pub struct NotImplementedIssuer {
    provider: ExternalInvoicingProvider,
}

impl NotImplementedIssuer {
    pub fn new(provider: ExternalInvoicingProvider) -> Self {
        Self { provider }
    }
}

#[async_trait::async_trait]
impl ExternalIssuer for NotImplementedIssuer {
    fn provider(&self) -> ExternalInvoicingProvider {
        self.provider
    }

    async fn issue(&self, _request: &IssuanceRequest) -> AppResult<IssuanceOutcome> {
        // `Internal` is the shape for "the server cannot do what you asked
        // but it is a known gap, not a client fault". A tenant that reached
        // here bypassed the dispatch below; the dispatch is what returns
        // the clean "pick one" or "none delegated" shape.
        Err(AppError::Internal(format!(
            "Invoicing through {} via this trait is not implemented; nothing in the repo \
             constructs an issuer for it.",
            self.provider.as_str()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_string_matches_the_integration_provider_discriminator() {
        assert_eq!(ExternalInvoicingProvider::Xero.as_str(), "xero");
        assert_eq!(ExternalInvoicingProvider::Quickbooks.as_str(), "quickbooks");
        assert_eq!(
            ExternalInvoicingProvider::parse("xero"),
            Some(ExternalInvoicingProvider::Xero)
        );
        assert_eq!(
            ExternalInvoicingProvider::parse("quickbooks"),
            Some(ExternalInvoicingProvider::Quickbooks)
        );
        assert_eq!(ExternalInvoicingProvider::parse("stripe"), None);
        assert_eq!(ExternalInvoicingProvider::parse(""), None);
    }

    #[test]
    fn an_empty_dispatch_picks_the_local_path() {
        let dispatch = DelegationDispatch::local_only();
        assert_eq!(dispatch.resolve().expect("no error"), None);
    }

    #[test]
    fn a_single_delegation_picks_that_provider() {
        let dispatch = DelegationDispatch::with(vec![ExternalInvoicingProvider::Xero]);
        assert_eq!(
            dispatch.resolve().expect("no error"),
            Some(ExternalInvoicingProvider::Xero)
        );
    }

    #[test]
    fn two_delegations_409_naming_the_conflict() {
        let dispatch = DelegationDispatch::with(vec![
            ExternalInvoicingProvider::Xero,
            ExternalInvoicingProvider::Quickbooks,
        ]);
        let err = dispatch.resolve().unwrap_err();
        match err {
            AppError::Conflict(message) => {
                assert!(message.contains("xero"), "names Xero: {message}");
                assert!(
                    message.contains("quickbooks"),
                    "names QuickBooks: {message}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_stub_issuer_refuses_naming_the_provider() {
        let issuer = NotImplementedIssuer::new(ExternalInvoicingProvider::Xero);
        let request = IssuanceRequest {
            local_invoice_id: uuid::Uuid::nil(),
            company_id: uuid::Uuid::nil(),
            total_minor: 10_000,
            currency: "USD".to_string(),
        };
        let err = issuer.issue(&request).await.unwrap_err();
        match err {
            AppError::Internal(message) => {
                assert!(message.contains("xero"), "names the provider: {message}");
                assert!(
                    message.contains("not implemented"),
                    "states it is unimplemented: {message}"
                );
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_stub_covers_quickbooks_too() {
        let issuer = NotImplementedIssuer::new(ExternalInvoicingProvider::Quickbooks);
        let request = IssuanceRequest {
            local_invoice_id: uuid::Uuid::nil(),
            company_id: uuid::Uuid::nil(),
            total_minor: 10_000,
            currency: "USD".to_string(),
        };
        let err = issuer.issue(&request).await.unwrap_err();
        assert!(matches!(err, AppError::Internal(_)));
    }
}
