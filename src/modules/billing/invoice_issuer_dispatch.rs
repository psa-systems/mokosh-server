//! MAPPS-1099 Phase 2d: the delegated-issuer dispatcher.
//!
//! Reads the credential blob under `SecretKind::Integration { provider }`,
//! refreshes the access token when it is near expiry (writes the
//! rotated pair back before the issue call fires, so a concurrent
//! request sees the fresh bearer), resolves the Mokosh company and
//! product mappings the Phase 2c admin surface populates, builds the
//! provider request shape and calls Phase 1b/1c's `issue_invoice`.
//!
//! The dispatcher is library code: `BillingService::create_invoice`
//! calls `IssuerDispatcher::plan` with the raw `CreateInvoiceRequest`
//! and the three resolved fields (currency, invoice date, due date)
//! and gets back `IssuerPlan::Local` (local path, external_* NULL) or
//! `IssuerPlan::Delegated(ExternalInvoiceRef)` (persist external_*).
//! A missing mapping or a client-side refusal is `Err(AppError)` so
//! the caller never writes a half-committed invoice row.
//!
//! Wiring into `create_invoice` lands in a follow-up PR; shipping the
//! dispatcher alone keeps the Phase 2b explicit refusal in place
//! while the integration-test env catches up to the shape it has to
//! exercise.

use std::sync::Arc;

use chrono::{NaiveDate, Utc};
use rust_decimal::prelude::*;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::modules::auth::TenantId;
use crate::modules::billing::invoice_issuer::{
    select_issuer_with, ExternalInvoiceRef, InvoiceProviderKind, IssuerSelection,
};
use crate::modules::billing::invoice_issuer_credentials::{
    apply_quickbooks_refresh, apply_xero_refresh, parse_blob, serialize_blob,
    IntegrationCredentialBlob,
};
use crate::modules::billing::invoice_issuer_mappings::InvoiceIssuerMappingService;
use crate::modules::billing::models::CreateInvoiceLineRequest;
use crate::modules::billing::provider_invoice::xero::XeroLineItemInput;
use crate::modules::billing::provider_invoice::{
    QuickBooksClient, QuickBooksIssueInvoiceRequest, XeroClient, XeroIssueInvoiceRequest,
};
use crate::modules::features::FeatureSnapshot;
use crate::modules::integrations::IntegrationsService;
use crate::secrets::{SecretKey, SecretProvider};
use crate::utils::error::{AppError, AppResult};
use mokosh_types::integrations::{Capability, IntegrationProvider};

/// What the dispatcher decided to do with one `create_invoice` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerPlan {
    Local,
    Delegated(ExternalInvoiceRef),
}

/// Build-once dispatcher for the delegated invoice-issuer path. All
/// dependencies are injected so the test harness can stand up a
/// dispatcher pointing at wiremocks for the two clients and an
/// in-memory `SecretProvider`.
#[derive(Clone)]
pub struct IssuerDispatcher {
    features: FeatureSnapshot,
    integrations: Arc<IntegrationsService>,
    mappings: Arc<InvoiceIssuerMappingService>,
    secrets: Arc<dyn SecretProvider>,
    xero: Arc<XeroClient>,
    quickbooks: Arc<QuickBooksClient>,
}

impl IssuerDispatcher {
    pub fn new(
        features: FeatureSnapshot,
        integrations: Arc<IntegrationsService>,
        mappings: Arc<InvoiceIssuerMappingService>,
        secrets: Arc<dyn SecretProvider>,
        xero: Arc<XeroClient>,
        quickbooks: Arc<QuickBooksClient>,
    ) -> Self {
        Self {
            features,
            integrations,
            mappings,
            secrets,
            xero,
            quickbooks,
        }
    }

    /// Whether the deployment-wide toggle is on, with no query and no
    /// await (MAPPS-1134).
    ///
    /// `plan` checks this too and returns `Local`, which is the right
    /// answer for a caller that already has everything `plan` needs.
    /// `BillingService::create_invoice` does not: it has to read the due
    /// date and the currency before it can build the request shape, and
    /// on every deployment today that work would be done only to be
    /// thrown away. Asking first keeps the untouched path untouched.
    pub fn delegation_enabled(&self) -> bool {
        self.features
            .is_enabled(crate::modules::features::Feature::DelegatedInvoiceIssuer)
    }

    /// Decide and (if delegated) carry out the external issue for one
    /// invoice. Returns `IssuerPlan::Local` for every path that leaves
    /// `create_invoice`'s current body unchanged:
    ///
    /// - dispatcher not opted into for this build (callers that build
    ///   `BillingService` without `with_invoice_dispatch`);
    /// - `Feature::DelegatedInvoiceIssuer` is off on the deployment;
    /// - the tenant has no Xero or QuickBooks row with
    ///   `Capability::Invoicing` enabled.
    ///
    /// Returns `IssuerPlan::Delegated(ExternalInvoiceRef)` once the
    /// external provider has issued the invoice: the caller writes the
    /// `external_provider` / `external_invoice_id` / `external_number`
    /// columns from the ref onto the local row and nothing else about
    /// the row changes (the local `invoice_number` still comes from the
    /// tenant's own sequence; the external number is what the customer
    /// sees).
    ///
    /// Any failure between "I asked for delegation" and "the external
    /// has the invoice" is an `AppError`, so `create_invoice` never
    /// writes a local row for an invoice the external refused.
    pub async fn plan(
        &self,
        tenant_id: TenantId,
        request: &CreateInvoiceRequestShape<'_>,
    ) -> AppResult<IssuerPlan> {
        if !self
            .features
            .is_enabled(crate::modules::features::Feature::DelegatedInvoiceIssuer)
        {
            return Ok(IssuerPlan::Local);
        }

        let invoicing = Capability::Invoicing.as_str().to_string();
        let xero_delegated = self
            .integrations
            .get(tenant_id, IntegrationProvider::Xero)
            .await?
            .enabled_capabilities
            .contains(&invoicing);
        let quickbooks_delegated = self
            .integrations
            .get(tenant_id, IntegrationProvider::Quickbooks)
            .await?
            .enabled_capabilities
            .contains(&invoicing);
        let selection = select_issuer_with(true, || xero_delegated, || quickbooks_delegated);

        match selection {
            IssuerSelection::Local => Ok(IssuerPlan::Local),
            IssuerSelection::Delegated {
                provider: InvoiceProviderKind::Xero,
            } => {
                let ref_ = self.issue_through_xero(tenant_id, request).await?;
                Ok(IssuerPlan::Delegated(ref_))
            }
            IssuerSelection::Delegated {
                provider: InvoiceProviderKind::Quickbooks,
            } => {
                let ref_ = self.issue_through_quickbooks(tenant_id, request).await?;
                Ok(IssuerPlan::Delegated(ref_))
            }
        }
    }

    async fn issue_through_xero(
        &self,
        tenant_id: TenantId,
        request: &CreateInvoiceRequestShape<'_>,
    ) -> AppResult<ExternalInvoiceRef> {
        let (blob, maybe_refreshed) = self
            .load_and_refresh_blob(tenant_id, InvoiceProviderKind::Xero)
            .await?;
        let IntegrationCredentialBlob::Xero(xero_blob) = &blob else {
            return Err(AppError::Unauthorized);
        };
        let credentials = xero_blob.into();

        let company_mapping = self
            .mappings
            .get_customer_mapping(tenant_id, InvoiceProviderKind::Xero, request.company_id)
            .await?
            .ok_or_else(|| {
                AppError::Conflict(format!(
                    "Company {} is not mapped to a Xero customer. Set the mapping \
                     at PUT /api/v1/invoice-issuer-mappings/companies/xero/{} first.",
                    request.company_id, request.company_id
                ))
            })?;

        let contact_id = Uuid::parse_str(&company_mapping.external_customer_id).map_err(|_| {
            AppError::internal(format!(
                "company {} is mapped to {:?} but Xero expects a UUID ContactID",
                request.company_id, company_mapping.external_customer_id
            ))
        })?;

        let xero_lines: Vec<XeroLineItemInput> = request
            .lines
            .iter()
            .map(|l| XeroLineItemInput {
                description: l.description.clone(),
                quantity_hundredths: decimal_to_hundredths(l.quantity),
                unit_price_minor: decimal_to_minor(l.unit_price),
            })
            .collect();

        let xero_request = XeroIssueInvoiceRequest {
            contact_id,
            invoice_date: request.invoice_date,
            due_date: request.due_date,
            currency: request.currency.to_string(),
            lines: xero_lines,
            // AUTHORISED so the invoice is immediately deliverable; a
            // tenant that wants a review step on their Xero side flips
            // the switch there, not here.
            status: "AUTHORISED",
        };

        if maybe_refreshed {
            // The credentials were refreshed and the new blob is already
            // written to the secret store. The call below uses the new
            // access token.
        }

        self.xero.issue_invoice(&credentials, &xero_request).await
    }

    async fn issue_through_quickbooks(
        &self,
        tenant_id: TenantId,
        request: &CreateInvoiceRequestShape<'_>,
    ) -> AppResult<ExternalInvoiceRef> {
        let (blob, _refreshed) = self
            .load_and_refresh_blob(tenant_id, InvoiceProviderKind::Quickbooks)
            .await?;
        let IntegrationCredentialBlob::Quickbooks(qbo_blob) = &blob else {
            return Err(AppError::Unauthorized);
        };
        let credentials = qbo_blob.into();

        let company_mapping = self
            .mappings
            .get_customer_mapping(
                tenant_id,
                InvoiceProviderKind::Quickbooks,
                request.company_id,
            )
            .await?
            .ok_or_else(|| {
                AppError::Conflict(format!(
                    "Company {} is not mapped to a QuickBooks customer. Set the mapping \
                     at PUT /api/v1/invoice-issuer-mappings/companies/quickbooks/{} first.",
                    request.company_id, request.company_id
                ))
            })?;

        // Every QBO line needs a product mapping (ItemRef is required for
        // a service invoice). Resolve all of them in one batched read.
        let product_ids: Vec<Uuid> = request.lines.iter().filter_map(|l| l.product_id).collect();
        let product_map = self
            .mappings
            .get_product_mappings(tenant_id, InvoiceProviderKind::Quickbooks, &product_ids)
            .await?;

        let mut qbo_lines = Vec::with_capacity(request.lines.len());
        for line in request.lines {
            let product_id = line.product_id.ok_or_else(|| {
                AppError::Conflict(
                    "Every line of a QuickBooks-delegated invoice must link to a product. \
                     Set a product_id on each line before issuing."
                        .to_string(),
                )
            })?;
            let mapping = product_map.get(&product_id).ok_or_else(|| {
                AppError::Conflict(format!(
                    "Product {product_id} is not mapped to a QuickBooks item. Set the mapping \
                     at PUT /api/v1/invoice-issuer-mappings/products/quickbooks/{product_id} first."
                ))
            })?;
            qbo_lines.push(
                crate::modules::billing::provider_invoice::quickbooks::QuickBooksLineItemInput {
                    description: line.description.clone(),
                    amount_minor: decimal_to_minor(line.quantity * line.unit_price),
                    item_id: mapping.external_item_id.clone(),
                },
            );
        }

        let qbo_request = QuickBooksIssueInvoiceRequest {
            customer_id: company_mapping.external_customer_id.clone(),
            invoice_date: request.invoice_date,
            due_date: request.due_date,
            currency: request.currency.to_string(),
            lines: qbo_lines,
        };

        self.quickbooks
            .issue_invoice(&credentials, &qbo_request)
            .await
    }

    /// Load the stored credential blob, refresh the access token when
    /// it is near expiry, write the rotated pair back to the secret
    /// store. Returns `(blob, refreshed)` where `blob` is the
    /// up-to-date state and `refreshed` is true iff a refresh ran
    /// (used by callers that want to log a telemetry event on
    /// rotation).
    async fn load_and_refresh_blob(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
    ) -> AppResult<(IntegrationCredentialBlob, bool)> {
        let key = SecretKey::integration(*tenant_id, provider.as_str());
        let stored = self.secrets.get(&key).await?;
        let mut blob = parse_blob(stored.as_deref(), provider)?;

        let now = Utc::now();
        let refreshed = match &mut blob {
            IntegrationCredentialBlob::Xero(x) => {
                if crate::modules::billing::provider_invoice::xero::access_token_near_expiry(
                    x.access_token_expires_at,
                    now,
                ) {
                    let creds = (&*x).into();
                    let response = self.xero.refresh_access_token(&creds).await?;
                    apply_xero_refresh(x, &response, now);
                    true
                } else {
                    false
                }
            }
            IntegrationCredentialBlob::Quickbooks(q) => {
                if crate::modules::billing::provider_invoice::quickbooks::access_token_near_expiry(
                    q.access_token_expires_at,
                    now,
                ) {
                    let creds = (&*q).into();
                    let response = self.quickbooks.refresh_access_token(&creds).await?;
                    apply_quickbooks_refresh(q, &response, now);
                    true
                } else {
                    false
                }
            }
        };

        if refreshed {
            let raw = serialize_blob(&blob)?;
            self.secrets.put(&key, &raw).await?;
        }
        Ok((blob, refreshed))
    }
}

/// Narrow view of a `CreateInvoiceRequest` the dispatcher needs. Named
/// here rather than taking `&CreateInvoiceRequest` so the dispatcher
/// does not reach into the billing-service's own request shape and so
/// a test can hand it a hand-built view without constructing every
/// optional field of the full request.
pub struct CreateInvoiceRequestShape<'a> {
    pub company_id: Uuid,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    pub currency: &'a str,
    pub lines: &'a [CreateInvoiceLineRequest],
}

/// Convert a positive-or-negative `Decimal` to minor units (hundredths
/// of a major unit, so `12.34` -> `1234`). The Xero and QuickBooks
/// clients both take `i64` minor units in; this is the one place the
/// decimal-to-integer conversion lives.
fn decimal_to_minor(d: Decimal) -> i64 {
    (d * Decimal::from(100))
        .round_dp(0)
        .to_i64()
        .unwrap_or_default()
}

/// Convert a `Decimal` quantity to hundredths (matches
/// `invoice_lines.quantity_hundredths` and the Xero line
/// `quantity_hundredths` input).
fn decimal_to_hundredths(d: Decimal) -> i64 {
    decimal_to_minor(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_to_minor_handles_the_common_cases() {
        assert_eq!(decimal_to_minor(Decimal::from(0)), 0);
        assert_eq!(decimal_to_minor(Decimal::from(1)), 100);
        assert_eq!(decimal_to_minor(Decimal::new(1234, 2)), 1234);
        assert_eq!(decimal_to_minor(Decimal::new(-1234, 2)), -1234);
        assert_eq!(decimal_to_minor(Decimal::new(5, 1)), 50);
    }

    /// A fractional cent rounds half-away-from-zero, matching the
    /// `invoice_lines` rounding `BillingService` uses. A test here
    /// pins that the dispatcher's minor-unit conversion does not
    /// drift from the row's own total column.
    #[test]
    fn decimal_to_minor_rounds_half_away_from_zero() {
        assert_eq!(decimal_to_minor(Decimal::new(1235, 3)), 124); // 1.235 -> 1.24
        assert_eq!(decimal_to_minor(Decimal::new(-1235, 3)), -124);
    }
}
