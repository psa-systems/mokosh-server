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

use super::{
    CheckoutParams, CheckoutSession, GatewayCheck, PaymentEvent, PaymentProvider, RefundLine,
    SetupIntentParams,
};
use crate::utils::error::{AppError, AppResult};

/// Stripe REST API base. Overridable via `STRIPE_API_BASE` so an integration
/// test can point the checkout call at a stub; defaults to the live host.
fn api_base() -> String {
    crate::config::get(&crate::config::registry::STRIPE_API_BASE)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.stripe.com".to_string())
}

/// A tenant's Stripe connection. Built per request from the decrypted config.
pub struct StripeProvider {
    /// The tenant's restricted secret key (`rk_live_...` / `sk_test_...`),
    /// the bearer for API calls. PMS-1181: never empty, because `from_config`
    /// refuses a blob missing it.
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
    // PMS-1181: both fields are `#[serde(default)]`, so the pre-MAPPS-759
    // blob (`{"api_key": ...}`, a shape nothing here reads) deserialised into
    // two empty strings and built a provider that could neither mint a
    // checkout nor verify a delivery, while the row reported itself
    // configured. Refuse it instead, and `gateway_ready` reports what is
    // actually true.
    let missing = super::blank_required_fields(&[
        ("secret_key", &creds.secret_key),
        ("webhook_secret", &creds.webhook_secret),
    ]);
    if !missing.is_empty() {
        return Err(super::incomplete_credentials("Stripe", &missing));
    }
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

    /// PMS-1181: check the two stored secrets, as far as Stripe allows.
    ///
    /// `GET /v1/account` is the cheapest call that proves the key: it needs no
    /// resource to exist and answers with the account the key belongs to, so a
    /// key for the wrong account or the wrong mode fails here rather than at a
    /// customer's checkout.
    ///
    /// The webhook signing secret has no remote check. Stripe does not expose
    /// an endpoint that takes one, and the only proof is a delivery it
    /// verifies, so the shape is checked here and the rest is reported as
    /// unchecked rather than dressed up as a pass.
    async fn check(&self) -> AppResult<Vec<GatewayCheck>> {
        let url = format!("{}/v1/account", api_base());
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.secret_key)
            .send()
            .await
            .map_err(|e| AppError::external_service("stripe", format!("request failed: {e}")))?;
        let status = resp.status();
        let body: Value =
            serde_json::from_str(&resp.text().await.unwrap_or_default()).unwrap_or(Value::Null);
        let key_check = if status.is_success() {
            GatewayCheck::passed("Secret key")
        } else {
            let detail = body["error"]["message"]
                .as_str()
                .unwrap_or("Stripe refused this key.");
            GatewayCheck::failed("Secret key", format!("{detail} ({status})"))
        };
        let webhook_check = if self.webhook_secret.starts_with("whsec_") {
            GatewayCheck::not_checkable(
                "Webhook signing secret",
                "Stripe offers no way to verify a signing secret without a delivery, so this one is stored but unproven.",
            )
        } else {
            // The endpoint URL pasted into the secret field is the common
            // version of this, and it is worth naming: it looks filled in and
            // refuses every delivery.
            GatewayCheck::failed(
                "Webhook signing secret",
                "This does not look like a Stripe signing secret; they begin with whsec_.",
            )
        };
        Ok(vec![key_check, webhook_check])
    }

    async fn capture(&self, order_id: &str) -> AppResult<()> {
        // Checkout charges when the buyer completes, so there is never anything
        // to capture. Reaching here means a `RequiresCapture` event was routed
        // to the wrong provider.
        Err(AppError::Configuration(format!(
            "stripe has no capture step; order {order_id:?} was routed to the wrong provider"
        )))
    }

    /// MAPPS-674: mint a Stripe Checkout Session in `mode: 'setup'`.
    ///
    /// Same POST endpoint as the payment mode above (Stripe's `mode` field
    /// picks between them), so a `setup` session is a payment session that
    /// stores the card without charging. Metadata stamps the tenant and the
    /// contact so the webhook receiver on `checkout.session.completed` can
    /// route the resulting row back to the calling contact without a
    /// database join. `payment_method_data[allow_redisplay] = always` lets
    /// Stripe show this card again on a future checkout session for the
    /// same Customer, which is the whole point of saving it.
    async fn create_setup_intent_session(
        &self,
        params: &SetupIntentParams<'_>,
    ) -> AppResult<CheckoutSession> {
        let mut form: Vec<(String, String)> = vec![
            ("mode".into(), "setup".into()),
            ("success_url".into(), params.success_url.to_string()),
            ("cancel_url".into(), params.cancel_url.to_string()),
            // Cards only for now; PayPal Reference Transactions is a
            // different surface tracked as a MAPPS-674 follow-up.
            ("payment_method_types[0]".into(), "card".into()),
            ("metadata[tenant_id]".into(), params.tenant_id.to_string()),
            ("metadata[contact_id]".into(), params.contact_id.to_string()),
            // Stamp the SetupIntent too so the setup.succeeded event (should
            // we ever move off checkout.session.completed) carries the same
            // reconciliation keys as the session that owns it.
            (
                "setup_intent_data[metadata][tenant_id]".into(),
                params.tenant_id.to_string(),
            ),
            (
                "setup_intent_data[metadata][contact_id]".into(),
                params.contact_id.to_string(),
            ),
        ];
        if let Some(email) = params.customer_email {
            form.push((String::from("customer_email"), email.to_string()));
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
            let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
            return Err(AppError::external_service(
                "stripe",
                format!("setup intent session failed ({status}): {msg}"),
            ));
        }
        let session_id = body["id"].as_str().unwrap_or_default().to_string();
        let checkout_url = body["url"].as_str().unwrap_or_default().to_string();
        if session_id.is_empty() || checkout_url.is_empty() {
            return Err(AppError::external_service(
                "stripe",
                "setup intent session response missing id/url",
            ));
        }
        Ok(CheckoutSession {
            session_id,
            url: checkout_url,
        })
    }

    /// MAPPS-674: `POST /v1/payment_methods/{pm}/detach`.
    ///
    /// Detach unlinks the PaymentMethod from every Customer it is attached
    /// to, so no future charge from us can reach the card. Called by the
    /// removal path BEFORE the `contact_payment_methods` row is deleted -
    /// if the detach fails we surface the error and keep the row, so the
    /// contact can retry; if the row deleted first and the detach then
    /// failed, the card would stay attached with no mokosh record of it.
    async fn detach_payment_method(&self, provider_pm_id: &str) -> AppResult<()> {
        if provider_pm_id.is_empty() {
            return Err(AppError::BadRequest(
                "Empty PaymentMethod id cannot be detached.".to_string(),
            ));
        }
        let url = format!(
            "{}/v1/payment_methods/{}/detach",
            api_base(),
            provider_pm_id
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.secret_key)
            .send()
            .await
            .map_err(|e| AppError::external_service("stripe", format!("request failed: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        // A PaymentMethod that is already detached returns 400 with a
        // `resource_missing` / already-detached code. Treat that as success
        // so a retry after a partial removal completes cleanly.
        let body: Value =
            serde_json::from_str(&resp.text().await.unwrap_or_default()).unwrap_or(Value::Null);
        let code = body["error"]["code"].as_str().unwrap_or_default();
        if code == "resource_missing" {
            return Ok(());
        }
        let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
        Err(AppError::external_service(
            "stripe",
            format!("detach payment method failed ({status}): {msg}"),
        ))
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
            // MAPPS-674: the session's `mode` decides which PaymentEvent
            // this becomes. `payment` (or a legacy blank, which Stripe
            // treats as `payment`) is a charge; `setup` is a
            // saved-card SetupIntent. Splitting here rather than at the
            // receiver means the dispatcher never has to know Stripe's
            // shape - one Stripe event maps to one PaymentEvent.
            match object["mode"].as_str().unwrap_or("payment") {
                "payment" => parse_stripe_payment_session(&event.raw, object, kind),
                "setup" => parse_stripe_setup_session(&event.raw, object, kind),
                _ => Ok(PaymentEvent::Ignored { kind }),
            }
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

/// Split out from [`parse_stripe_event`] so a `checkout.session.completed`
/// in `mode: 'payment'` keeps the exact pre-MAPPS-674 shape.
fn parse_stripe_payment_session(
    raw: &Value,
    object: &Value,
    kind: String,
) -> AppResult<PaymentEvent> {
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
        raw: raw.clone(),
    })
}

/// MAPPS-674: parse a `checkout.session.completed` in `mode: 'setup'` into
/// [`PaymentEvent::PaymentMethodAttached`]. Reads:
///
/// - `customer` for the Stripe Customer id (the card owner on Stripe's side).
/// - `setup_intent` for the SetupIntent id, then reads the `payment_method`
///   off the object itself, since the session carries the expanded
///   PaymentMethod on completion.
/// - `metadata.tenant_id` / `metadata.contact_id`, stamped at mint time
///   by [`StripeProvider::create_setup_intent_session`].
/// - The `card` block for the display digest (brand + last4 + exp_month +
///   exp_year), never the PAN or CVV.
///
/// Any field absent means an unrelated session on the tenant's account,
/// which is [`PaymentEvent::Ignored`] so the receiver 200s and the provider
/// stops retrying.
fn parse_stripe_setup_session(
    raw: &Value,
    object: &Value,
    kind: String,
) -> AppResult<PaymentEvent> {
    if object["status"].as_str() != Some("complete") {
        return Ok(PaymentEvent::Ignored { kind });
    }
    let provider_customer_id = match object["customer"].as_str() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return Ok(PaymentEvent::Ignored { kind }),
    };
    // The session carries the SetupIntent with the newly attached
    // PaymentMethod. Stripe returns it either expanded (an object with
    // `payment_method` inside) or as a plain id string; both need reading.
    let setup_intent = &object["setup_intent"];
    let payment_method = if setup_intent.is_object() {
        setup_intent["payment_method"].clone()
    } else {
        object["payment_method"].clone()
    };
    let provider_pm_id = match payment_method_id(&payment_method) {
        Some(id) => id,
        None => return Ok(PaymentEvent::Ignored { kind }),
    };
    let tenant_id = object["metadata"]["tenant_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok());
    let contact_id = object["metadata"]["contact_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok());
    let (Some(tenant_id), Some(contact_id)) = (tenant_id, contact_id) else {
        return Ok(PaymentEvent::Ignored { kind });
    };
    // The card block is only present when the PaymentMethod is expanded;
    // absent means "someone attached a non-card via API", which we do not
    // support here yet - ignore rather than fabricate a display digest.
    let card = if payment_method.is_object() {
        &payment_method["card"]
    } else {
        &Value::Null
    };
    let brand = card["brand"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let last4 = card["last4"].as_str().unwrap_or_default().to_string();
    let exp_month = card["exp_month"].as_i64().unwrap_or(0);
    let exp_year = card["exp_year"].as_i64().unwrap_or(0);
    if brand.is_empty() || last4.is_empty() || exp_month == 0 || exp_year == 0 {
        return Ok(PaymentEvent::Ignored { kind });
    }
    Ok(PaymentEvent::PaymentMethodAttached {
        provider_pm_id,
        provider_customer_id,
        tenant_id,
        contact_id,
        brand,
        last4,
        exp_month: exp_month as u8,
        exp_year: exp_year as u16,
        raw: raw.clone(),
    })
}

/// Extract a PaymentMethod id from an expanded object or a plain string;
/// anything else is `None`.
fn payment_method_id(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    if value.is_object() {
        if let Some(id) = value["id"].as_str().filter(|s| !s.is_empty()) {
            return Some(id.to_string());
        }
    }
    None
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
