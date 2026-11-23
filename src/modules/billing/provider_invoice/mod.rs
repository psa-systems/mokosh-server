//! MAPPS-1099 Phase 1b/1c: external invoice-issuer clients.
//!
//! One module per provider, matching the `src/modules/billing/provider/`
//! shape the payment-provider plane already uses. Each client is
//! responsible for OAuth 2.0 token refresh, HTTP calls to its provider,
//! translation of our row shape into the provider's wire shape, and the
//! provider's own retry policy (Xero's 429 Retry-After, QuickBooks's
//! own throttle). These clients are not mounted on the HTTP surface; they
//! are called by the `InvoiceIssuer` dispatch in
//! `billing::invoice_issuer_dispatch`, which selects a client per tenant
//! and drives issue, credit note, void, bill and settlement reads.
//!
//! Why no `issue_invoice` stub on `BillingService`: a route or a service
//! method that returns `NotImplemented` for an installed integration is the
//! "advertises what the build cannot deliver" anti-pattern MAPPS-1098 and
//! MAPPS-1102 enforce against. Callers go through the dispatch instead.

pub mod quickbooks;
pub mod xero;

pub use quickbooks::{
    QuickBooksClient, QuickBooksCredentials, QuickBooksInvoiceStatus,
    QuickBooksIssueInvoiceRequest, QuickBooksTokenResponse,
};
pub use xero::{
    XeroClient, XeroCredentials, XeroInvoiceStatus, XeroIssueInvoiceRequest, XeroTokenResponse,
};
