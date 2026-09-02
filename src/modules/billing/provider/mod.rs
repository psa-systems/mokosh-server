//! PMS-711: payment-provider abstraction for invoice "Pay Now".
//!
//! One trait, [`PaymentProvider`], models everything the billing service needs
//! from a third-party gateway: mint a hosted checkout session for an invoice
//! balance, and turn an inbound signed webhook into a normalised
//! [`PaymentEvent`]. Stripe is the first (and, in this cut, only) implementation
//! ([`stripe::StripeProvider`]); adding PayPal is a new `impl PaymentProvider`,
//! not a change to `BillingService`.
//!
//! PMS-966: that last sentence used to be an intention rather than a fact. The
//! trait existed and was never dispatched through - `BillingService` held a
//! `StripeProvider` concretely and all three credential lookups carried
//! `provider = 'stripe'` as a SQL literal, while `GatewayProvider` already
//! accepted `paypal` and `authorize_net`, so a tenant could store an active
//! config for a provider nothing could serve and get silence for it. [`build`]
//! is now the one place a stored discriminator becomes a provider, and
//! [`is_supported`] is the one place that answers whether it can.
//!
//! Credentials are per-tenant and write-only (PMS-342): the tenant's provider
//! secret lives encrypted in `payment_gateway_configs.config_encrypted` and is
//! decrypted strictly server-side to build a provider instance. It is never
//! returned to a client and never logged.

use async_trait::async_trait;
use axum::http::HeaderMap;
use rust_decimal::Decimal;
use serde_json::Value;
use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};

pub mod paypal;
pub mod stripe;
pub use paypal::PaypalProvider;
pub use stripe::StripeProvider;

/// Every provider discriminator this build can actually serve.
///
/// `GatewayProvider` is the wider set: it knows `authorize_net` and `paypal`
/// too, and the `payment_gateway_configs.provider` CHECK constraint accepts all
/// three, because the column predates any implementation. This is the narrower,
/// honest list, and it is what the config write path validates against so a
/// tenant cannot activate a gateway that will never mint a checkout session.
pub const SUPPORTED: &[&str] = &["stripe", "paypal"];

/// Whether [`build`] can produce a provider for this discriminator.
pub fn is_supported(provider: &str) -> bool {
    SUPPORTED.contains(&provider)
}

/// Turn a stored `(provider, decrypted config)` pair into a provider.
///
/// The ONE place a discriminator becomes an implementation. Every caller that
/// used to name `StripeProvider` goes through here instead, which is what makes
/// a second provider a new arm rather than a change to `BillingService`.
///
/// Parsing the credential blob belongs to the provider module, not here: each
/// provider's config is its own shape, so the alternative is one struct that is
/// the union of every provider's fields with everything optional.
pub fn build(
    provider: &str,
    plaintext: &str,
    http: reqwest::Client,
) -> AppResult<Box<dyn PaymentProvider>> {
    match provider {
        "stripe" => Ok(Box::new(stripe::from_config(plaintext, http)?)),
        "paypal" => Ok(Box::new(paypal::from_config(plaintext, http)?)),
        // Unreachable for a config written after PMS-966, which refuses to
        // activate an unsupported provider. Reachable for a row stored before
        // it, so it is a stated error rather than a panic or a silent skip.
        other => Err(AppError::Configuration(format!(
            "payment provider {other:?} is configured but not implemented; supported: {}",
            SUPPORTED.join(", ")
        ))),
    }
}

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
    /// The buyer approved a checkout and the provider is waiting for the
    /// merchant to charge them (PMS-969). Stripe never emits this: Checkout
    /// charges when the buyer completes. A PayPal Order with `intent=CAPTURE`
    /// is only approved at that point, and the money moves when the merchant
    /// calls capture, so the receiver answers this by calling
    /// [`PaymentProvider::capture`] and lets the resulting completed-capture
    /// event record the payment through the normal path.
    RequiresCapture { order_id: String },
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

    /// Verify the inbound webhook, then parse the body into a normalised event.
    /// Returns `Unauthorized` on a bad or missing signature; the raw body must
    /// not be trusted before verification passes.
    ///
    /// Takes the whole header map and is async (PMS-969). The first version
    /// took one `signature: &str` and was sync, which was Stripe's shape and
    /// nobody else's: PayPal signs across five headers and its supported
    /// verification is a call to PayPal, so the provider picks its own headers
    /// out and may do I/O to check them.
    async fn verify_and_parse_webhook(
        &self,
        raw_body: &[u8],
        headers: &HeaderMap,
    ) -> AppResult<PaymentEvent>;

    /// Charge an approved checkout (PMS-969). Only meaningful for a provider
    /// that emits [`PaymentEvent::RequiresCapture`]; a provider that charges
    /// on completion returns an error, because being asked means the receiver
    /// has confused which provider it is talking to.
    async fn capture(&self, order_id: &str) -> AppResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim `build` exists to make: one arm per servable provider, and a
    /// stated refusal for everything else.
    #[test]
    fn only_a_supported_provider_builds() {
        let http = reqwest::Client::new();
        let config = r#"{"secret_key":"sk_test","webhook_secret":"whsec_test"}"#;

        assert!(build("stripe", config, http.clone()).is_ok());
        assert!(build("paypal", config, http.clone()).is_ok());

        for unsupported in ["authorize_net", "", "STRIPE", "PayPal"] {
            // `Box<dyn PaymentProvider>` is not `Debug`, so this matches rather
            // than calling `expect_err`.
            match build(unsupported, config, http.clone()) {
                Err(AppError::Configuration(message)) => {
                    assert!(
                        message.contains("not implemented"),
                        "{unsupported:?} refused for the wrong reason: {message}"
                    );
                }
                Err(other) => panic!("{unsupported:?} should be a Configuration error: {other:?}"),
                Ok(_) => panic!("{unsupported:?} must not build"),
            }
        }
    }

    /// `SUPPORTED` and `build` are two statements of the same fact, and a
    /// provider added to one and not the other is the bug this catches:
    /// `is_supported` gates activation, `build` runs at payment time, so a
    /// disagreement means a gateway that switches on and then cannot charge.
    #[test]
    fn the_supported_list_and_the_build_arms_agree() {
        let http = reqwest::Client::new();
        // Deliberately not a real credential blob: every supported provider
        // must at least reach its own parser rather than fall to the catch-all.
        for id in SUPPORTED {
            assert!(is_supported(id), "{id} is listed but not supported");
            let err = build(id, "{}", http.clone());
            let reached_the_arm = match err {
                Ok(_) => true,
                Err(AppError::Configuration(ref m)) => !m.contains("not implemented"),
                Err(_) => true,
            };
            assert!(reached_the_arm, "{id} is listed but has no arm in build");
        }
        assert!(
            !is_supported("authorize_net"),
            "authorize_net has no implementation"
        );
    }

    /// The discriminator is the stored column value, so it must match what a
    /// built provider reports about itself. A mismatch would resolve one
    /// tenant's row into a provider that signs with another scheme.
    #[test]
    fn a_built_provider_reports_the_id_it_was_asked_for() {
        let http = reqwest::Client::new();
        let config = r#"{"secret_key":"sk_test","webhook_secret":"whsec_test"}"#;
        let p = build("stripe", config, http).expect("stripe builds");
        assert_eq!(p.id(), "stripe");
    }
}
