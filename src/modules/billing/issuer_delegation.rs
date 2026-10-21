//! MAPPS-1099 scaffold: the `InvoiceIssuer` seam a later phase plugs
//! external invoicing providers (Xero, QuickBooks) into.
//!
//! An invoice is "issued" by assigning a number, writing the row and
//! putting it in front of the customer. Today Mokosh does all three; a
//! tenant that delegates the Invoicing capability to Xero or QuickBooks
//! wants an external provider to do them, with Mokosh keeping a mirror row
//! for history and reconciliation.
//!
//! This file DOES NOT change the current issuance path. It declares the
//! trait and the external-provider enum future phases of MAPPS-1099
//! implement:
//!
//! - **Phase A (not shipped):** the Xero API client + OAuth. ~800-1500
//!   LOC in `src/modules/billing/provider/xero.rs`.
//! - **Phase B (not shipped):** the QuickBooks API client + OAuth.
//!   `src/modules/billing/provider/quickbooks.rs`.
//! - **Phase C (not shipped):** the delegation layer that reads
//!   `IntegrationsService::get(tenant, provider).enabled_capabilities`
//!   in `billing::service::create_invoice` and picks the issuer.
//! - **Phase D (not shipped):** signed webhook receivers at
//!   `/api/v1/webhooks/{xero,quickbooks}` for payment-received and
//!   voided events.
//!
//! The trait + enum here are the API SHAPE those phases build against,
//! and they produce an `InvoicingNotImplementedForProvider` error today
//! so a hypothetical caller that bypassed the dispatch and asked for
//! external issuance before the clients exist gets a clear refusal.
//!
//! # Why this ships before the clients
//!
//! Three reasons.
//!
//! 1. The migration (278) that adds the `invoices.external_provider`,
//!    `external_invoice_id` and `external_number` columns ships here so
//!    the schema is ready to receive the first client's writes without
//!    needing a schema change in the same PR as the client code (a
//!    schema change rolled back for a client bug would roll back both).
//! 2. The trait pins the shape the clients implement, so Xero and
//!    QuickBooks (siblings, not shared) land as two independent PRs
//!    without having to re-litigate the issuer surface.
//! 3. A unit test here asserts that the external path currently refuses:
//!    the "no capability delegated silently falls through to local"
//!    invariant is checked at the enum level, so the eventual Phase C
//!    dispatch cannot accidentally route a non-delegated tenant to a
//!    stubbed external path.
//!
//! Nothing in `billing::service` reads this file yet. The seam is here
//! waiting for Phase C to call it.

use crate::utils::error::{AppError, AppResult};

/// The external provider for one tenant's Invoicing delegation. The three
/// providers the registry declares that could ever receive this delegation
/// are declared one at a time as they ship; today none ship, so this is
/// shaped for extension.
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
/// invoice document. Kept minimal on purpose: Phase A will grow the shape
/// as the first real client discovers what it actually needs. The default
/// stub below never reads these fields.
///
/// Shape is deliberately a struct (versus a trait method with 20
/// parameters) so adding a field in Phase A does not break the trait
/// signature.
#[derive(Debug, Clone)]
pub struct IssuanceRequest {
    /// Mokosh's own invoice id, so a webhook update from the provider
    /// can find the local mirror row.
    pub local_invoice_id: uuid::Uuid,
    /// The company this invoice bills. Resolved by the caller to a
    /// provider-specific contact id in Phase A (Xero needs the Contact
    /// GUID; QuickBooks needs the Customer id).
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
    /// local mirror row needs. Phase A implements this for Xero; Phase B
    /// for QuickBooks. Today's stub returns `NotImplemented`.
    async fn issue(&self, request: &IssuanceRequest) -> AppResult<IssuanceOutcome>;
}

/// Phase C will build this from `IntegrationsService::get(tenant, provider)`
/// for each provider in the tenant's integrations rows whose
/// `enabled_capabilities` carries `invoicing`, and will pick the one to
/// dispatch to. Today the function has no caller and returns `None` so a
/// callsite under test can confirm the local path is picked when no
/// provider is delegated.
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
    /// the integrations rows. The caller is in `billing::service` once
    /// Phase C lands; the dispatch's job is just the arithmetic over the
    /// resolved set.
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

/// Today's placeholder for every variant of [`ExternalInvoicingProvider`].
/// Phase A replaces `Xero` with the real `XeroInvoiceIssuer`; Phase B
/// replaces `Quickbooks` with `QuickbooksInvoiceIssuer`. Named so a stray
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
            "Invoicing through {} is not yet implemented. The clients land in later phases of \
             MAPPS-1099; until then the local Mokosh path is the only issuance path served.",
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
    async fn the_stub_issuer_refuses_with_a_named_phase_pointer() {
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
                    message.contains("MAPPS-1099"),
                    "names the ticket: {message}"
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
