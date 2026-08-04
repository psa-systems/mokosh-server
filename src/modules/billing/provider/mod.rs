//! PMS-711: payment-provider abstraction for invoice "Pay Now".
//!
//! One trait, [`PaymentProvider`], models everything the billing service needs
//! from a third-party gateway: mint a hosted checkout session for an invoice
//! balance, and turn an inbound signed webhook into a normalised
//! [`PaymentEvent`]. Stripe is the first (and, in this cut, only) implementation
//! ([`stripe::StripeProvider`]); adding PayPal is a new `impl PaymentProvider`,
//! not a change to `BillingService`.
//!
//! Credentials are per-tenant and write-only (PMS-342): the tenant's provider
//! secret lives encrypted in `payment_gateway_configs.config_encrypted` and is
//! decrypted strictly server-side to build a provider instance. It is never
//! returned to a client and never logged.

use async_trait::async_trait;
use rust_decimal::Decimal;
use serde_json::Value;
use uuid::Uuid;

use crate::utils::error::AppResult;

pub mod stripe;
pub use stripe::StripeProvider;

/// Inputs for a hosted checkout session covering one invoice's balance.
pub struct CheckoutParams<'a> {
    pub tenant_id: Uuid,
    pub invoice_id: Uuid,
    /// Human invoice number, shown as the checkout line-item name.
    pub invoice_number: &'a str,
    /// Amount to charge in the invoice's major currency units (e.g. `12.50`).
    pub amount: Decimal,
    /// ISO-4217 code (e.g. `USD`). Passed to the provider lowercased.
    pub currency: &'a str,
    /// Where the provider returns the payer after success / cancel.
    pub success_url: &'a str,
    pub cancel_url: &'a str,
    /// Recipient email, pre-filled on the checkout page when known.
    pub customer_email: Option<&'a str>,
}

/// A created hosted-checkout session. The caller redirects the payer to `url`.
#[derive(Debug, Clone)]
pub struct CheckoutSession {
    pub session_id: String,
    pub url: String,
}

/// One refund inside a [`PaymentEvent::Refunded`].
#[derive(Debug, Clone)]
pub struct RefundLine {
    /// Provider refund id (Stripe `re_...`); the refund idempotency key.
    pub provider_reference: String,
    /// Refunded amount in major currency units.
    pub amount: Decimal,
}

/// Normalised inbound webhook event. Adapters collapse their provider-specific
/// event zoo down to this closed set so the billing service stays
/// provider-agnostic.
#[derive(Debug, Clone)]
pub enum PaymentEvent {
    /// A checkout / payment completed successfully.
    PaymentSucceeded {
        /// Provider payment reference (Stripe `payment_intent` id). Stored as
        /// the payment's `gateway_transaction_id` and matched by later refunds.
        provider_reference: String,
        /// Tenant + invoice recovered from the session metadata we set at
        /// creation time.
        tenant_id: Uuid,
        invoice_id: Uuid,
        /// Paid amount in major currency units.
        amount: Decimal,
        currency: String,
        /// The full event JSON, persisted to `payments.gateway_response`.
        raw: Value,
    },
    /// One or more refunds against a prior successful payment.
    Refunded {
        /// The original payment's provider reference (Stripe `payment_intent`).
        provider_reference: String,
        currency: String,
        refunds: Vec<RefundLine>,
        raw: Value,
    },
    /// A recognised event we deliberately do not act on (abandoned checkout,
    /// failed payment intent, an unrelated session on the tenant's account,
    /// ...). Carried rather than error'd so the handler returns 200 and the
    /// provider stops retrying.
    Ignored { kind: String },
}

/// A tenant-configured payment provider. One implementation per provider;
/// adding PayPal is a new impl, not a change to the billing service (PMS-711).
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Provider discriminator, matching `GatewayProvider::as_str`.
    fn id(&self) -> &'static str;

    /// Create a hosted checkout session for one invoice balance.
    async fn create_checkout_session(
        &self,
        params: &CheckoutParams<'_>,
    ) -> AppResult<CheckoutSession>;

    /// Verify the webhook signature over the raw request bytes, then parse the
    /// body into a normalised event. Returns `Unauthorized` on a bad or missing
    /// signature; the raw body must not be trusted before verification passes.
    fn verify_and_parse_webhook(&self, raw_body: &[u8], signature: &str)
        -> AppResult<PaymentEvent>;
}
