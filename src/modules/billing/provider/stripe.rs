//! PMS-711: Stripe implementation of [`PaymentProvider`].
//!
//! Uses the tenant's own restricted secret key (stored write-only in
//! `payment_gateway_configs`), so a Checkout Session is created ON the tenant's
//! Stripe account and funds settle to them, not to the platform. This is the
//! per-tenant-credentials model: the platform is not in the money flow.
//!
//! Two surfaces:
//! - [`StripeProvider::create_checkout_session`] POSTs to
//!   `POST /v1/checkout/sessions` with the tenant key as the Bearer, embedding
//!   `{tenant_id, invoice_id}` in the session + payment-intent metadata so the
//!   webhook can reconcile the payment back to the invoice.
//! - [`StripeProvider::verify_and_parse_webhook`] verifies the `Stripe-Signature`
//!   scheme (`t=<ts>,v1=<hmac>`) over the raw bytes and maps the event to a
//!   [`PaymentEvent`].
//!
//! Zero-decimal currencies (JPY, ...) are out of scope: amounts are converted
//! at 100 minor units per major unit. Every currency mokosh invoices in today
//! is two-decimal, so this holds; a follow-up adds an exponent table when a
//! zero-decimal currency is first supported.

use async_trait::async_trait;
use dunite_stripe_core::{
    from_minor_units, parse_event_envelope, to_minor_units, verify_webhook_signature,
    DEFAULT_TOLERANCE_SECS,
};
use serde_json::Value;
use uuid::Uuid;

use super::{CheckoutParams, CheckoutSession, PaymentEvent, PaymentProvider, RefundLine};
use crate::utils::error::{AppError, AppResult};

/// Stripe REST API base. Overridable via `STRIPE_API_BASE` so an integration
/// test can point the checkout call at a stub; defaults to the live host.
fn api_base() -> String {
    std::env::var("STRIPE_API_BASE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.stripe.com".to_string())
}

/// A tenant's Stripe connection. Built per request from the decrypted config.
pub struct StripeProvider {
    /// The tenant's restricted secret key (`rk_live_...` / `sk_test_...`).
    /// Bearer for API calls; empty is acceptable on the webhook-only path.
    secret_key: String,
    /// The tenant's webhook signing secret (`whsec_...`).
    webhook_secret: String,
    http: reqwest::Client,
}

/// Shape of the decrypted `payment_gateway_configs.config_encrypted` blob for
/// this provider. Both fields are write-only secrets: the tenant's restricted
/// API key and the webhook signing secret. Never logged, never returned to a
/// client (PMS-342).
///
/// It lives here rather than in `BillingService` because it is Stripe's shape
/// and nobody else's: PayPal's credential is not a `secret_key` plus a
/// `webhook_secret`, so a single service-level struct would have to become a
/// union of every provider's fields (PMS-966).
#[derive(serde::Deserialize)]
struct StripeCredentials {
    #[serde(default)]
    secret_key: String,
    #[serde(default)]
    webhook_secret: String,
}

/// Build a provider from the decrypted config blob.
///
/// A blob that does not parse is a `Configuration` error and not a 500 with a
/// serde message: the operator stored it, so the fix is theirs, and the error
/// text must never carry the plaintext it failed to parse.
pub fn from_config(plaintext: &str, http: reqwest::Client) -> AppResult<StripeProvider> {
    let creds: StripeCredentials = serde_json::from_str(plaintext).map_err(|_| {
        AppError::Configuration("stored Stripe config is not valid JSON".to_string())
    })?;
    Ok(StripeProvider::new(
        creds.secret_key,
        creds.webhook_secret,
        http,
    ))
}

impl StripeProvider {
    pub fn new(secret_key: String, webhook_secret: String, http: reqwest::Client) -> Self {
        Self {
            secret_key,
            webhook_secret,
            http,
        }
    }
}

#[async_trait]
impl PaymentProvider for StripeProvider {
    fn id(&self) -> &'static str {
        "stripe"
    }

    async fn create_checkout_session(
        &self,
        params: &CheckoutParams<'_>,
    ) -> AppResult<CheckoutSession> {
        let unit_amount = to_minor_units(params.amount).map_err(|_| {
            AppError::BadRequest(format!("Amount {} is out of range", params.amount))
        })?;
        let currency = params.currency.to_ascii_lowercase();
        let tenant = params.tenant_id.to_string();
        let invoice = params.invoice_id.to_string();
        let unit_amount = unit_amount.to_string();
        let line_item_name = format!("Invoice {}", params.invoice_number);

        // Stripe takes application/x-www-form-urlencoded with bracketed nested
        // keys. `client_reference_id` + metadata carry our reconciliation keys;
        // `payment_intent_data[metadata]` copies them onto the PaymentIntent so
        // both the checkout.session.completed and any later charge event can be
        // traced back to the invoice.
        let mut form: Vec<(String, String)> = vec![
            ("mode".into(), "payment".into()),
            ("success_url".into(), params.success_url.to_string()),
            ("cancel_url".into(), params.cancel_url.to_string()),
            ("client_reference_id".into(), invoice.clone()),
            ("line_items[0][quantity]".into(), "1".into()),
            ("line_items[0][price_data][currency]".into(), currency),
            ("line_items[0][price_data][unit_amount]".into(), unit_amount),
            (
                "line_items[0][price_data][product_data][name]".into(),
                line_item_name,
            ),
            ("metadata[tenant_id]".into(), tenant.clone()),
            ("metadata[invoice_id]".into(), invoice.clone()),
            ("payment_intent_data[metadata][tenant_id]".into(), tenant),
            ("payment_intent_data[metadata][invoice_id]".into(), invoice),
        ];
        if let Some(email) = params.customer_email {
            form.push(("customer_email".into(), email.to_string()));
        }

        let url = format!("{}/v1/checkout/sessions", api_base());
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.secret_key)
            .form(&form)
            .send()
            .await
            .map_err(|e| AppError::external_service("stripe", format!("request failed: {e}")))?;

        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| AppError::external_service("stripe", format!("response not JSON: {e}")))?;

        if !status.is_success() {
            // Surface Stripe's own error message but never the request (which
            // carried the tenant key). A 401/403 here means the tenant's key is
            // wrong or lacks the checkout permission.
            let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
            return Err(AppError::external_service(
                "stripe",
                format!("checkout session failed ({status}): {msg}"),
            ));
        }

        let session_id = body["id"].as_str().unwrap_or_default().to_string();
        let checkout_url = body["url"].as_str().unwrap_or_default().to_string();
        if session_id.is_empty() || checkout_url.is_empty() {
            return Err(AppError::external_service(
                "stripe",
                "checkout session response missing id/url",
            ));
        }
        Ok(CheckoutSession {
            session_id,
            url: checkout_url,
        })
    }

    async fn verify_and_parse_webhook(
        &self,
        raw_body: &[u8],
        headers: &axum::http::HeaderMap,
    ) -> AppResult<PaymentEvent> {
        // Missing or non-ASCII header = 401 before the body is looked at.
        let signature = headers
            .get(SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        let now = chrono::Utc::now().timestamp();
        // DEV-514: the constant-time signature verifier lives in the shared
        // dunite-stripe-core crate (also consumed by a8n-tools and bunyip).
        verify_webhook_signature(
            self.webhook_secret.as_bytes(),
            raw_body,
            signature,
            DEFAULT_TOLERANCE_SECS,
            now,
        )
        .map_err(|_| AppError::Unauthorized)?;
        parse_stripe_event(raw_body)
    }

    async fn capture(&self, order_id: &str) -> AppResult<()> {
        // Checkout charges when the buyer completes, so there is never anything
        // to capture. Reaching here means a `RequiresCapture` event was routed
        // to the wrong provider.
        Err(AppError::Configuration(format!(
            "stripe has no capture step; order {order_id:?} was routed to the wrong provider"
        )))
    }
}

/// Stripe's signature header name.
const SIGNATURE_HEADER: &str = "Stripe-Signature";

/// Map a verified Stripe event body to a normalised [`PaymentEvent`].
///
/// Anything we do not act on - including a `checkout.session.completed` whose
/// `payment_status` is not `paid`, or one missing our metadata (an unrelated
/// session on the tenant's account) - becomes [`PaymentEvent::Ignored`] so the
/// handler answers 200 rather than provoking retries.
fn parse_stripe_event(raw_body: &[u8]) -> AppResult<PaymentEvent> {
    // DEV-514: envelope parse (id + type + raw JSON) comes from the shared
    // dunite-stripe-core crate; mokosh maps `data.object` to its own
    // PaymentEvent below.
    let event = parse_event_envelope(raw_body)
        .map_err(|_| AppError::BadRequest("Malformed Stripe event body".to_string()))?;
    let kind = event.kind.clone();
    let object = &event.raw["data"]["object"];

    match kind.as_str() {
        "checkout.session.completed" => {
            if object["payment_status"].as_str() != Some("paid") {
                return Ok(PaymentEvent::Ignored { kind });
            }
            let provider_reference = match object["payment_intent"].as_str() {
                Some(pi) if !pi.is_empty() => pi.to_string(),
                _ => return Ok(PaymentEvent::Ignored { kind }),
            };
            let tenant_id = object["metadata"]["tenant_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok());
            let invoice_id = object["metadata"]["invoice_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok());
            let amount_total = object["amount_total"].as_i64();
            let (Some(tenant_id), Some(invoice_id), Some(amount_total)) =
                (tenant_id, invoice_id, amount_total)
            else {
                // Legit Stripe event, but not one of ours (no metadata) or
                // missing the amount. Do not act, do not retry.
                return Ok(PaymentEvent::Ignored { kind });
            };
            Ok(PaymentEvent::PaymentSucceeded {
                provider_reference,
                tenant_id,
                invoice_id,
                amount: from_minor_units(amount_total),
                currency: object["currency"]
                    .as_str()
                    .unwrap_or("usd")
                    .to_ascii_uppercase(),
                raw: event.raw,
            })
        }
        "charge.refunded" => {
            let provider_reference = match object["payment_intent"].as_str() {
                Some(pi) if !pi.is_empty() => pi.to_string(),
                _ => return Ok(PaymentEvent::Ignored { kind }),
            };
            let currency = object["currency"]
                .as_str()
                .unwrap_or("usd")
                .to_ascii_uppercase();
            // A charge carries the cumulative list of every refund against it,
            // each with its own id. Recording all of them with ON CONFLICT DO
            // NOTHING on the refund id makes redelivery + incremental refunds
            // both idempotent: only refunds not yet seen actually insert.
            let refunds: Vec<RefundLine> = object["refunds"]["data"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| {
                            let id = r["id"].as_str()?.to_string();
                            let amount = from_minor_units(r["amount"].as_i64()?);
                            Some(RefundLine {
                                provider_reference: id,
                                amount,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            if refunds.is_empty() {
                return Ok(PaymentEvent::Ignored { kind });
            }
            Ok(PaymentEvent::Refunded {
                provider_reference,
                currency,
                refunds,
                raw: event.raw,
            })
        }
        _ => Ok(PaymentEvent::Ignored { kind }),
    }
}

#[cfg(test)]
mod tests {
    // DEV-514: the Stripe-Signature verifier + money conversion now live in
    // dunite-stripe-core and are unit-tested there; these tests cover mokosh's
    // own event -> PaymentEvent mapping on top of the shared envelope parse.
    use super::*;
    use rust_decimal::Decimal;

    #[test]
    fn parse_maps_a_paid_checkout_to_payment_succeeded() {
        let tenant = Uuid::new_v4();
        let invoice = Uuid::new_v4();
        let body = serde_json::json!({
            "id": "evt_test",
            "type": "checkout.session.completed",
            "data": {"object": {
                "payment_status": "paid",
                "payment_intent": "pi_123",
                "amount_total": 12500,
                "currency": "usd",
                "metadata": {"tenant_id": tenant, "invoice_id": invoice}
            }}
        })
        .to_string();
        match parse_stripe_event(body.as_bytes()).unwrap() {
            PaymentEvent::PaymentSucceeded {
                provider_reference,
                tenant_id,
                invoice_id,
                amount,
                currency,
                ..
            } => {
                assert_eq!(provider_reference, "pi_123");
                assert_eq!(tenant_id, tenant);
                assert_eq!(invoice_id, invoice);
                assert_eq!(amount, Decimal::new(12500, 2));
                assert_eq!(currency, "USD");
            }
            other => panic!("expected PaymentSucceeded, got {other:?}"),
        }
    }

    #[test]
    fn parse_ignores_an_unpaid_checkout_session() {
        let body = serde_json::json!({
            "id": "evt_test",
            "type": "checkout.session.completed",
            "data": {"object": {"payment_status": "unpaid", "payment_intent": "pi_1"}}
        })
        .to_string();
        assert!(matches!(
            parse_stripe_event(body.as_bytes()).unwrap(),
            PaymentEvent::Ignored { .. }
        ));
    }

    #[test]
    fn parse_ignores_a_checkout_session_without_our_metadata() {
        // A real paid session created outside mokosh on the tenant's account.
        let body = serde_json::json!({
            "id": "evt_test",
            "type": "checkout.session.completed",
            "data": {"object": {
                "payment_status": "paid",
                "payment_intent": "pi_9",
                "amount_total": 500,
                "currency": "usd",
                "metadata": {}
            }}
        })
        .to_string();
        assert!(matches!(
            parse_stripe_event(body.as_bytes()).unwrap(),
            PaymentEvent::Ignored { .. }
        ));
    }

    #[test]
    fn parse_maps_a_charge_refunded_to_refund_lines() {
        let body = serde_json::json!({
            "id": "evt_test",
            "type": "charge.refunded",
            "data": {"object": {
                "payment_intent": "pi_123",
                "currency": "usd",
                "refunds": {"data": [
                    {"id": "re_1", "amount": 500},
                    {"id": "re_2", "amount": 250}
                ]}
            }}
        })
        .to_string();
        match parse_stripe_event(body.as_bytes()).unwrap() {
            PaymentEvent::Refunded {
                provider_reference,
                refunds,
                currency,
                ..
            } => {
                assert_eq!(provider_reference, "pi_123");
                assert_eq!(currency, "USD");
                assert_eq!(refunds.len(), 2);
                assert_eq!(refunds[0].provider_reference, "re_1");
                assert_eq!(refunds[0].amount, Decimal::new(500, 2));
                assert_eq!(refunds[1].amount, Decimal::new(250, 2));
            }
            other => panic!("expected Refunded, got {other:?}"),
        }
    }

    #[test]
    fn parse_ignores_an_unhandled_event_type() {
        let body = br#"{"id":"evt_x","type":"payment_intent.payment_failed","data":{"object":{}}}"#;
        match parse_stripe_event(body).unwrap() {
            PaymentEvent::Ignored { kind } => {
                assert_eq!(kind, "payment_intent.payment_failed")
            }
            other => panic!("expected Ignored, got {other:?}"),
        }
    }
}
