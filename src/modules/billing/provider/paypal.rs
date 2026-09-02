//! PMS-969: PayPal implementation of [`PaymentProvider`].
//!
//! The tenant's own REST app credentials (`client_id` + `client_secret`, stored
//! write-only through `crate::secrets`), so an Order is created ON the tenant's
//! PayPal account and funds settle to them, not to the platform. Same
//! per-tenant-credentials model as Stripe: the platform is not in the money
//! flow.
//!
//! Three surfaces, and two of them differ from Stripe in ways worth knowing:
//!
//! - [`PaypalProvider::create_checkout_session`] POSTs an Order with
//!   `intent=CAPTURE`, carrying `tenant_id` and `invoice_id` in the purchase
//!   unit's `custom_id` so the capture event can be reconciled back to the
//!   invoice. The approve link is the checkout URL.
//! - [`PaypalProvider::verify_and_parse_webhook`] does NOT verify a signature
//!   locally. PayPal signs RSA-SHA256 over `id|time|webhook_id|crc32(body)`
//!   against a certificate it serves at a URL in the request headers; checking
//!   that here would mean RSA and X.509 parsing plus an outbound fetch to a
//!   request-supplied URL, which is the surface PMS-805 screens for. PayPal's
//!   supported path is to send the headers and body back to
//!   `POST /v1/notifications/verify-webhook-signature` and be told SUCCESS or
//!   FAILURE, so that is what this does. One round-trip per webhook, on the
//!   pre-auth path, accepted for the reason PMS-967 accepted one: PayPal
//!   retries a failed delivery with backoff for days, so an outage is a delay
//!   and not a lost payment.
//! - [`PaypalProvider::capture`] exists because PayPal does not charge on its
//!   own. An approved Order is only approved; the merchant calls capture.
//!   `CHECKOUT.ORDER.APPROVED` maps to [`PaymentEvent::RequiresCapture`], the
//!   receiver calls this, and the resulting `PAYMENT.CAPTURE.COMPLETED`
//!   records the payment through the normal path.
//!
//! Amounts are decimal strings in PayPal's API (`"12.50"`), so there is no
//! minor-unit conversion and no zero-decimal-currency caveat here.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::http::HeaderMap;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::{CheckoutParams, CheckoutSession, PaymentEvent, PaymentProvider, RefundLine};
use crate::utils::error::{AppError, AppResult};

/// PayPal REST API base. Overridable via `PAYPAL_API_BASE` so an integration
/// test can point every call at a stub, exactly as `STRIPE_API_BASE` does for
/// Stripe. When unset, the credential's `sandbox` flag picks the host.
fn api_base(sandbox: bool) -> String {
    if let Some(base) = std::env::var("PAYPAL_API_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        return base.trim_end_matches('/').to_string();
    }
    if sandbox {
        "https://api-m.sandbox.paypal.com".to_string()
    } else {
        "https://api-m.paypal.com".to_string()
    }
}

/// The five headers PayPal signs a delivery with. Their values are passed back
/// to PayPal verbatim; nothing here interprets them.
const TRANSMISSION_ID: &str = "paypal-transmission-id";
const TRANSMISSION_TIME: &str = "paypal-transmission-time";
const TRANSMISSION_SIG: &str = "paypal-transmission-sig";
const CERT_URL: &str = "paypal-cert-url";
const AUTH_ALGO: &str = "paypal-auth-algo";

/// Refresh the OAuth token this far before PayPal says it expires.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(300);

/// Shape of the decrypted config blob for this provider. All write-only
/// (PMS-342), never logged, never returned to a client.
///
/// `sandbox` lives here rather than reading the gateway row's `is_test_mode`,
/// because whether a client id belongs to a sandbox app is a property of the
/// credential, the way `sk_test_` is a property of a Stripe key. Keeping it
/// in the blob is also what leaves `provider::build` and the resolution
/// queries untouched.
#[derive(serde::Deserialize)]
struct PaypalCredentials {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    /// The webhook's id from the tenant's PayPal app, which the verify call
    /// needs to know which webhook the delivery claims to be from.
    #[serde(default)]
    webhook_id: String,
    #[serde(default)]
    sandbox: bool,
}

/// Build a provider from the decrypted config blob.
pub fn from_config(plaintext: &str, http: reqwest::Client) -> AppResult<PaypalProvider> {
    let creds: PaypalCredentials = serde_json::from_str(plaintext).map_err(|_| {
        AppError::Configuration("stored PayPal config is not valid JSON".to_string())
    })?;
    Ok(PaypalProvider::new(
        creds.client_id,
        creds.client_secret,
        creds.webhook_id,
        creds.sandbox,
        http,
    ))
}

struct AccessToken {
    value: String,
    expires_at: Instant,
}

/// A tenant's PayPal connection. Built per request from the decrypted config;
/// the OAuth token is cached for that instance's lifetime, which in practice is
/// one request.
pub struct PaypalProvider {
    client_id: String,
    client_secret: String,
    webhook_id: String,
    sandbox: bool,
    http: reqwest::Client,
    token: Arc<RwLock<Option<AccessToken>>>,
}

impl PaypalProvider {
    pub fn new(
        client_id: String,
        client_secret: String,
        webhook_id: String,
        sandbox: bool,
        http: reqwest::Client,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            webhook_id,
            sandbox,
            http,
            token: Arc::new(RwLock::new(None)),
        }
    }

    fn base(&self) -> String {
        api_base(self.sandbox)
    }

    /// Client-credentials grant against the tenant's app. A 401 here means the
    /// tenant's credentials are wrong, surfaced as an external-service error
    /// that names the provider and never the credential.
    async fn access_token(&self) -> AppResult<String> {
        {
            let cached = self.token.read().await;
            if let Some(t) = cached.as_ref() {
                if Instant::now() + TOKEN_EXPIRY_MARGIN < t.expires_at {
                    return Ok(t.value.clone());
                }
            }
        }
        let url = format!("{}/v1/oauth2/token", self.base());
        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await
            .map_err(|e| {
                AppError::external_service("paypal", format!("token request failed: {e}"))
            })?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| {
            AppError::external_service("paypal", format!("token response not JSON: {e}"))
        })?;
        if !status.is_success() {
            let msg = body["error_description"]
                .as_str()
                .or(body["error"].as_str())
                .unwrap_or("unknown error");
            return Err(AppError::external_service(
                "paypal",
                format!("authentication failed ({status}): {msg}"),
            ));
        }
        let value = body["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::external_service("paypal", "token response missing access_token")
            })?
            .to_string();
        let expires_in = body["expires_in"].as_u64().unwrap_or(0);
        let mut cached = self.token.write().await;
        *cached = Some(AccessToken {
            value: value.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in),
        });
        Ok(value)
    }

    /// One authenticated JSON POST, with PayPal's error message surfaced and the
    /// request (which carried the tenant's token) never echoed.
    async fn post_json(&self, path: &str, body: &Value) -> AppResult<(reqwest::StatusCode, Value)> {
        let token = self.access_token().await?;
        let url = format!("{}{}", self.base(), path);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(|e| AppError::external_service("paypal", format!("request failed: {e}")))?;
        let status = resp.status();
        // A 204 (capture of an already-captured order returns one) has no body.
        let text = resp.text().await.unwrap_or_default();
        let body: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map_err(|e| {
                AppError::external_service("paypal", format!("response not JSON: {e}"))
            })?
        };
        Ok((status, body))
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[async_trait]
impl PaymentProvider for PaypalProvider {
    fn id(&self) -> &'static str {
        "paypal"
    }

    async fn create_checkout_session(
        &self,
        params: &CheckoutParams<'_>,
    ) -> AppResult<CheckoutSession> {
        // `custom_id` is the reconciliation key: PayPal copies it from the
        // purchase unit onto the capture, so the capture-completed event can
        // name the invoice without a second lookup. `reference_id` carries the
        // invoice alone for the same reason Stripe's `client_reference_id`
        // does. Both are capped at 127 characters by PayPal; two uuids and a
        // separator are 73.
        let custom_id = format!("{}:{}", params.tenant_id, params.invoice_id);
        let mut payment_source = json!({
            "paypal": {
                "experience_context": {
                    "user_action": "PAY_NOW",
                    "return_url": params.success_url,
                    "cancel_url": params.cancel_url,
                }
            }
        });
        if let Some(email) = params.customer_email {
            payment_source["paypal"]["email_address"] = json!(email);
        }
        let order = json!({
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": params.invoice_id.to_string(),
                "custom_id": custom_id,
                "description": format!("Invoice {}", params.invoice_number),
                "amount": {
                    "currency_code": params.currency.to_ascii_uppercase(),
                    "value": params.amount.round_dp(2).to_string(),
                }
            }],
            "payment_source": payment_source,
        });

        let (status, body) = self.post_json("/v2/checkout/orders", &order).await?;
        if !status.is_success() {
            let msg = body["details"][0]["description"]
                .as_str()
                .or(body["message"].as_str())
                .unwrap_or("unknown error");
            return Err(AppError::external_service(
                "paypal",
                format!("order creation failed ({status}): {msg}"),
            ));
        }

        let session_id = body["id"].as_str().unwrap_or_default().to_string();
        // The buyer-facing link is `payer-action` when a payment_source is
        // given and `approve` otherwise; accept either so the shape of the
        // request above can change without breaking the response parse.
        let url = body["links"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|l| matches!(l["rel"].as_str(), Some("payer-action") | Some("approve")))
            .and_then(|l| l["href"].as_str())
            .unwrap_or_default()
            .to_string();
        if session_id.is_empty() || url.is_empty() {
            return Err(AppError::external_service(
                "paypal",
                "order response missing id or approve link",
            ));
        }
        Ok(CheckoutSession { session_id, url })
    }

    async fn verify_and_parse_webhook(
        &self,
        raw_body: &[u8],
        headers: &HeaderMap,
    ) -> AppResult<PaymentEvent> {
        // All five headers or nothing: a missing one is an unauthenticated
        // request, not a malformed one, and the body is not parsed before the
        // check passes.
        let transmission_id = header(headers, TRANSMISSION_ID).ok_or(AppError::Unauthorized)?;
        let transmission_time = header(headers, TRANSMISSION_TIME).ok_or(AppError::Unauthorized)?;
        let transmission_sig = header(headers, TRANSMISSION_SIG).ok_or(AppError::Unauthorized)?;
        let cert_url = header(headers, CERT_URL).ok_or(AppError::Unauthorized)?;
        let auth_algo = header(headers, AUTH_ALGO).ok_or(AppError::Unauthorized)?;

        // The verify call takes the event as JSON, and PayPal compares it to
        // what it delivered. This is why the route is exempt from
        // `sanitize_json_body`: a byte rewritten on the way in is a FAILURE on
        // the way out.
        let event: Value = serde_json::from_slice(raw_body)
            .map_err(|_| AppError::BadRequest("Malformed PayPal event body".to_string()))?;

        let request = json!({
            "transmission_id": transmission_id,
            "transmission_time": transmission_time,
            "transmission_sig": transmission_sig,
            "cert_url": cert_url,
            "auth_algo": auth_algo,
            "webhook_id": self.webhook_id,
            "webhook_event": event,
        });
        let (status, body) = self
            .post_json("/v1/notifications/verify-webhook-signature", &request)
            .await?;
        if !status.is_success() {
            return Err(AppError::external_service(
                "paypal",
                format!("webhook verification call failed ({status})"),
            ));
        }
        if body["verification_status"].as_str() != Some("SUCCESS") {
            return Err(AppError::Unauthorized);
        }
        parse_paypal_event(&event)
    }

    async fn capture(&self, order_id: &str) -> AppResult<()> {
        let path = format!(
            "/v2/checkout/orders/{}/capture",
            urlencoding::encode(order_id)
        );
        let (status, body) = self.post_json(&path, &json!({})).await?;
        // 201 on first capture. A repeat delivery of the approval finds the
        // order already captured and PayPal answers 422 ORDER_ALREADY_CAPTURED;
        // that is success for our purposes, since the money moved and the
        // capture event is what records it.
        if status.is_success() {
            return Ok(());
        }
        let issue = body["details"][0]["issue"].as_str().unwrap_or_default();
        if status.as_u16() == 422 && issue == "ORDER_ALREADY_CAPTURED" {
            return Ok(());
        }
        let msg = body["details"][0]["description"]
            .as_str()
            .or(body["message"].as_str())
            .unwrap_or("unknown error");
        Err(AppError::external_service(
            "paypal",
            format!("capture of order {order_id} failed ({status}): {msg}"),
        ))
    }
}

/// Recover `(tenant_id, invoice_id)` from the `custom_id` this module wrote at
/// order creation. Anything else is a resource created outside mokosh on the
/// tenant's account, which is ignored rather than refused.
fn parse_custom_id(custom_id: Option<&str>) -> Option<(Uuid, Uuid)> {
    let (tenant, invoice) = custom_id?.split_once(':')?;
    Some((tenant.parse().ok()?, invoice.parse().ok()?))
}

fn parse_amount(amount: &Value) -> Option<(Decimal, String)> {
    let value: Decimal = amount["value"].as_str()?.parse().ok()?;
    let currency = amount["currency_code"].as_str()?.to_ascii_uppercase();
    Some((value, currency))
}

/// Map a verified PayPal event to a normalised [`PaymentEvent`].
///
/// Anything not acted on becomes [`PaymentEvent::Ignored`] so the receiver
/// answers 200 and PayPal stops retrying.
fn parse_paypal_event(event: &Value) -> AppResult<PaymentEvent> {
    let kind = event["event_type"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("PayPal event has no event_type".to_string()))?
        .to_string();
    let resource = &event["resource"];

    match kind.as_str() {
        // The buyer approved; nothing has been charged. The receiver captures.
        "CHECKOUT.ORDER.APPROVED" => {
            if parse_custom_id(resource["purchase_units"][0]["custom_id"].as_str()).is_none() {
                return Ok(PaymentEvent::Ignored { kind });
            }
            match resource["id"].as_str() {
                Some(id) if !id.is_empty() => Ok(PaymentEvent::RequiresCapture {
                    order_id: id.to_string(),
                }),
                _ => Ok(PaymentEvent::Ignored { kind }),
            }
        }
        // Money moved. The capture id is the payment's provider reference and
        // what a later refund names.
        "PAYMENT.CAPTURE.COMPLETED" => {
            if resource["status"].as_str() != Some("COMPLETED") {
                return Ok(PaymentEvent::Ignored { kind });
            }
            let Some((tenant_id, invoice_id)) = parse_custom_id(resource["custom_id"].as_str())
            else {
                return Ok(PaymentEvent::Ignored { kind });
            };
            let Some(provider_reference) = resource["id"].as_str().filter(|s| !s.is_empty()) else {
                return Ok(PaymentEvent::Ignored { kind });
            };
            let Some((amount, currency)) = parse_amount(&resource["amount"]) else {
                return Ok(PaymentEvent::Ignored { kind });
            };
            Ok(PaymentEvent::PaymentSucceeded {
                provider_reference: provider_reference.to_string(),
                tenant_id,
                invoice_id,
                amount,
                currency,
                raw: event.clone(),
            })
        }
        // A refund against a capture. The resource is the refund; the capture
        // it reverses is under `links` as the `up` relation
        // (`.../v2/payments/captures/{id}`), which is the documented place and
        // the only one present on every refund event.
        "PAYMENT.CAPTURE.REFUNDED" => {
            let Some(capture_id) = resource["links"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|l| l["rel"].as_str() == Some("up"))
                .and_then(|l| l["href"].as_str())
                .and_then(|href| href.rsplit('/').next())
                .filter(|s| !s.is_empty())
            else {
                return Ok(PaymentEvent::Ignored { kind });
            };
            let Some(refund_id) = resource["id"].as_str().filter(|s| !s.is_empty()) else {
                return Ok(PaymentEvent::Ignored { kind });
            };
            let Some((amount, currency)) = parse_amount(&resource["amount"]) else {
                return Ok(PaymentEvent::Ignored { kind });
            };
            Ok(PaymentEvent::Refunded {
                provider_reference: capture_id.to_string(),
                currency,
                refunds: vec![RefundLine {
                    provider_reference: refund_id.to_string(),
                    amount,
                }],
                raw: event.clone(),
            })
        }
        _ => Ok(PaymentEvent::Ignored { kind }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4())
    }

    #[test]
    fn a_completed_capture_maps_to_payment_succeeded() {
        let (tenant, invoice) = ids();
        let event = json!({
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "id": "CAP123",
                "status": "COMPLETED",
                "custom_id": format!("{tenant}:{invoice}"),
                "amount": {"currency_code": "usd", "value": "125.00"}
            }
        });
        match parse_paypal_event(&event).unwrap() {
            PaymentEvent::PaymentSucceeded {
                provider_reference,
                tenant_id,
                invoice_id,
                amount,
                currency,
                ..
            } => {
                assert_eq!(provider_reference, "CAP123");
                assert_eq!(tenant_id, tenant);
                assert_eq!(invoice_id, invoice);
                assert_eq!(amount, Decimal::new(12500, 2));
                assert_eq!(currency, "USD");
            }
            other => panic!("expected PaymentSucceeded, got {other:?}"),
        }
    }

    #[test]
    fn an_approved_order_asks_to_be_captured() {
        let (tenant, invoice) = ids();
        let event = json!({
            "event_type": "CHECKOUT.ORDER.APPROVED",
            "resource": {
                "id": "ORDER1",
                "purchase_units": [{"custom_id": format!("{tenant}:{invoice}")}]
            }
        });
        assert!(matches!(
            parse_paypal_event(&event).unwrap(),
            PaymentEvent::RequiresCapture { order_id } if order_id == "ORDER1"
        ));
    }

    /// An order created outside mokosh on the tenant's account carries no
    /// custom_id of ours, and must be ignored rather than captured: capturing
    /// it would charge a buyer for something mokosh knows nothing about.
    #[test]
    fn an_approved_order_that_is_not_ours_is_not_captured() {
        let event = json!({
            "event_type": "CHECKOUT.ORDER.APPROVED",
            "resource": {"id": "ORDER2", "purchase_units": [{"custom_id": "their-own-ref"}]}
        });
        assert!(matches!(
            parse_paypal_event(&event).unwrap(),
            PaymentEvent::Ignored { .. }
        ));
    }

    #[test]
    fn a_refund_names_the_capture_it_reverses() {
        let event = json!({
            "event_type": "PAYMENT.CAPTURE.REFUNDED",
            "resource": {
                "id": "REF9",
                "amount": {"currency_code": "USD", "value": "25.00"},
                "links": [
                    {"rel": "self", "href": "https://api.paypal.com/v2/payments/refunds/REF9"},
                    {"rel": "up", "href": "https://api.paypal.com/v2/payments/captures/CAP123"}
                ]
            }
        });
        match parse_paypal_event(&event).unwrap() {
            PaymentEvent::Refunded {
                provider_reference,
                refunds,
                currency,
                ..
            } => {
                assert_eq!(provider_reference, "CAP123");
                assert_eq!(currency, "USD");
                assert_eq!(refunds.len(), 1);
                assert_eq!(refunds[0].provider_reference, "REF9");
                assert_eq!(refunds[0].amount, Decimal::new(2500, 2));
            }
            other => panic!("expected Refunded, got {other:?}"),
        }
    }

    #[test]
    fn a_capture_without_our_custom_id_is_ignored() {
        let event = json!({
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {"id": "CAPX", "status": "COMPLETED", "custom_id": "not-ours",
                         "amount": {"currency_code": "USD", "value": "1.00"}}
        });
        assert!(matches!(
            parse_paypal_event(&event).unwrap(),
            PaymentEvent::Ignored { .. }
        ));
    }

    #[test]
    fn an_unhandled_event_type_is_ignored() {
        let event = json!({"event_type": "BILLING.SUBSCRIPTION.CREATED", "resource": {}});
        assert!(matches!(
            parse_paypal_event(&event).unwrap(),
            PaymentEvent::Ignored { kind } if kind == "BILLING.SUBSCRIPTION.CREATED"
        ));
    }

    /// The reconciliation key must survive the round trip through PayPal's
    /// `custom_id`, and anything else must resolve to nothing rather than to a
    /// wrong pair.
    #[test]
    fn custom_id_round_trips_and_rejects_everything_else() {
        let (tenant, invoice) = ids();
        assert_eq!(
            parse_custom_id(Some(&format!("{tenant}:{invoice}"))),
            Some((tenant, invoice))
        );
        for bad in [None, Some(""), Some("no-colon"), Some("a:b"), Some("::")] {
            assert!(parse_custom_id(bad).is_none(), "{bad:?} must not parse");
        }
    }
}
