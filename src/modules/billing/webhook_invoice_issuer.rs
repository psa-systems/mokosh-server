//! MAPPS-1099 Phase 3 scaffolds: signed webhook verifiers for the Xero
//! and QuickBooks event streams.
//!
//! Xero and QuickBooks both deliver account-change events (invoice
//! paid, invoice voided, invoice amended) as signed POSTs. Phase 3b
//! wires the actual event handling (map the external invoice id back
//! to a local row via `invoices.external_invoice_id`, update status
//! from the payload, write an audit entry); this PR lands the
//! signature verifiers alone so the next step is adding routes against
//! a library it already carries, not building both at once.
//!
//! Both schemes verify as HMAC-SHA256 over the raw request body,
//! base64-encoded, compared constant-time. The signing key is the
//! installation's own webhook secret, written to `SecretKind::Integration`
//! during OAuth consent in the Phase 2c reconnect flow.
//!
//! Nothing mounts routes yet; the signatures of these helpers match
//! the shape every provider webhook in `src/modules/billing/webhook.rs`
//! already uses (`verify_and_parse_webhook` on `PaymentProvider`), so
//! Phase 3b's receiver code calls these verifiers directly without
//! re-shaping them.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Verify a Xero webhook delivery.
///
/// Xero sends the `x-xero-signature` header carrying `base64(hmac_sha256(body, webhook_signing_key))`.
/// A tampered body (or a wrong key) fails the HMAC compare; a well-known-false
/// return is the only outcome besides a well-known-true, so the caller cannot
/// confuse a key mismatch with an outage. Comparison is constant-time to deny
/// a timing side channel on signature-length prefixes.
pub fn verify_xero_signature(body: &[u8], signature_header: &str, signing_key: &[u8]) -> bool {
    verify_hmac_sha256_base64(body, signature_header.trim(), signing_key)
}

/// Verify a QuickBooks webhook delivery.
///
/// QuickBooks sends the `intuit-signature` header carrying
/// `base64(hmac_sha256(body, verifier_token))`. Same shape as Xero's
/// verifier; the only difference is the header the HTTP handler reads
/// it from. Kept as a dedicated fn for the same reason
/// `provider::stripe::verify_and_parse_webhook` is dedicated: the
/// callers downstream dispatch on the provider, and one named fn per
/// provider keeps the dispatch straight when a header name changes.
pub fn verify_quickbooks_signature(
    body: &[u8],
    signature_header: &str,
    verifier_token: &[u8],
) -> bool {
    verify_hmac_sha256_base64(body, signature_header.trim(), verifier_token)
}

/// Shared HMAC-SHA256 + base64 verifier used by both providers. Private
/// because it names no provider: a caller that wants to add a third
/// provider on this scheme goes through [`verify_xero_signature`] or
/// [`verify_quickbooks_signature`] by analogy, so the provider list
/// stays in the module interface and not scattered through callers.
fn verify_hmac_sha256_base64(body: &[u8], signature_b64: &str, key: &[u8]) -> bool {
    let Ok(expected_bytes) = BASE64_STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(body);
    // `verify_slice` runs the constant-time compare the Hmac crate
    // documents is the right primitive here; we never read the raw
    // computed bytes out of `mac` and compare with `==`.
    mac.verify_slice(&expected_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-good HMAC-SHA256 round-trip. Signs a body with a key, then
    /// verifies the base64 signature it produces; a tiny body mutation
    /// turns the verifier false. This is the invariant Phase 3b's event
    /// handling leans on: a tampered payload cannot reach the
    /// local-row update path.
    #[test]
    fn xero_verifier_accepts_a_signature_produced_with_the_same_key() {
        let body = b"{\"events\":[]}";
        let key = b"secret-xero-webhook-key-at-least-32-bytes";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());

        assert!(verify_xero_signature(body, &sig, key));

        let tampered = b"{\"events\":[1]}";
        assert!(
            !verify_xero_signature(tampered, &sig, key),
            "a body mutation must fail the verifier"
        );

        let wrong_key = b"not-the-key";
        assert!(
            !verify_xero_signature(body, &sig, wrong_key),
            "a key mismatch must fail the verifier"
        );
    }

    #[test]
    fn quickbooks_verifier_accepts_a_signature_produced_with_the_same_token() {
        let body = b"{\"eventNotifications\":[]}";
        let token = b"quickbooks-verifier-token";
        let mut mac = HmacSha256::new_from_slice(token).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());

        assert!(verify_quickbooks_signature(body, &sig, token));

        let tampered = b"{\"eventNotifications\":[{}]}";
        assert!(
            !verify_quickbooks_signature(tampered, &sig, token),
            "a body mutation must fail the verifier"
        );
    }

    #[test]
    fn a_malformed_base64_signature_fails_the_verifier_rather_than_erroring_out() {
        let body = b"{}";
        let key = b"k";
        assert!(!verify_xero_signature(body, "@@not-base64@@", key));
        assert!(!verify_quickbooks_signature(body, "@@not-base64@@", key));
    }

    #[test]
    fn an_empty_body_still_verifies_with_a_matching_signature() {
        let body: &[u8] = b"";
        let key = b"edge-case-key";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());
        assert!(verify_xero_signature(body, &sig, key));
        assert!(verify_quickbooks_signature(body, &sig, key));
    }

    /// The verifiers tolerate the leading / trailing whitespace a proxy
    /// sometimes adds on a header, so a valid signature does not fail
    /// over a transport quirk. Matching the Stripe-signature verifier's
    /// `trim()` posture (provider::stripe).
    #[test]
    fn leading_whitespace_on_the_header_is_tolerated() {
        let body = b"{}";
        let key = b"k";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());
        let padded = format!(" {sig}  ");
        assert!(verify_xero_signature(body, &padded, key));
    }
}

// ---------------------------------------------------------------------------
// MAPPS-1136: the receivers.
// ---------------------------------------------------------------------------

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use uuid::Uuid;

use crate::modules::auth::TenantId;
use crate::modules::billing::invoice_issuer::InvoiceProviderKind;
use crate::modules::billing::invoice_issuer_dispatch::{ExternalInvoiceState, IssuerDispatcher};
use crate::modules::billing::service::BillingService;
use crate::utils::error::{AppError, AppResult};

/// State for one invoice-issuer webhook mount.
///
/// The dispatcher is here because it already owns the credential load, the
/// near-expiry refresh and the two clients, and a webhook needs all three:
/// the signing key to verify with, and a call to the provider to find out
/// what actually changed. A second credential path for the receiver is the
/// thing this avoids.
#[derive(Clone)]
pub struct InvoiceIssuerWebhookState {
    pub billing: Arc<BillingService>,
    pub dispatcher: Arc<IssuerDispatcher>,
    /// Which provider this mount serves, so one handler serves both.
    pub provider: InvoiceProviderKind,
}

/// Xero's delivery. `events` is empty on the "intent to receive"
/// validation call Xero makes when a subscription is created or changed,
/// which must answer 2xx or the subscription is never activated.
#[derive(Debug, Deserialize)]
struct XeroDelivery {
    #[serde(default)]
    events: Vec<XeroEvent>,
}

#[derive(Debug, Deserialize)]
struct XeroEvent {
    #[serde(rename = "resourceId", default)]
    resource_id: String,
    #[serde(rename = "eventCategory", default)]
    event_category: String,
}

/// Intuit's delivery.
#[derive(Debug, Deserialize)]
struct QuickBooksDelivery {
    #[serde(rename = "eventNotifications", default)]
    event_notifications: Vec<QuickBooksNotification>,
}

#[derive(Debug, Deserialize)]
struct QuickBooksNotification {
    #[serde(rename = "dataChangeEvent", default)]
    data_change_event: Option<QuickBooksDataChange>,
}

#[derive(Debug, Deserialize, Default)]
struct QuickBooksDataChange {
    #[serde(default)]
    entities: Vec<QuickBooksEntity>,
}

#[derive(Debug, Deserialize)]
struct QuickBooksEntity {
    #[serde(rename = "name", default)]
    name: String,
    #[serde(rename = "id", default)]
    id: String,
}

/// The invoice ids one delivery names, in the order the provider sent
/// them.
///
/// Only invoice events: both providers multiplex every resource type they
/// were subscribed to onto one stream, and a contact or a payment event
/// names an id that is not an invoice id. Looking those up would find
/// nothing, which is harmless, but it would also record a delivery as
/// "matched nothing" when the honest answer is that it was never about an
/// invoice.
fn invoice_ids(provider: InvoiceProviderKind, body: &[u8]) -> AppResult<Vec<String>> {
    match provider {
        InvoiceProviderKind::Xero => {
            let delivery: XeroDelivery = serde_json::from_slice(body)
                .map_err(|e| AppError::BadRequest(format!("unreadable Xero delivery: {e}")))?;
            Ok(delivery
                .events
                .into_iter()
                .filter(|e| e.event_category.eq_ignore_ascii_case("INVOICE"))
                .map(|e| e.resource_id)
                .filter(|id| !id.is_empty())
                .collect())
        }
        InvoiceProviderKind::Quickbooks => {
            let delivery: QuickBooksDelivery = serde_json::from_slice(body).map_err(|e| {
                AppError::BadRequest(format!("unreadable QuickBooks delivery: {e}"))
            })?;
            Ok(delivery
                .event_notifications
                .into_iter()
                .filter_map(|n| n.data_change_event)
                .flat_map(|c| c.entities)
                .filter(|e| e.name.eq_ignore_ascii_case("Invoice"))
                .map(|e| e.id)
                .filter(|id| !id.is_empty())
                .collect())
        }
    }
}

/// The header each provider puts its signature in.
fn signature_header(provider: InvoiceProviderKind, headers: &HeaderMap) -> Option<&str> {
    let name = match provider {
        InvoiceProviderKind::Xero => "x-xero-signature",
        InvoiceProviderKind::Quickbooks => "intuit-signature",
    };
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn verify(provider: InvoiceProviderKind, body: &[u8], signature: &str, key: &str) -> bool {
    match provider {
        InvoiceProviderKind::Xero => verify_xero_signature(body, signature, key.as_bytes()),
        InvoiceProviderKind::Quickbooks => {
            verify_quickbooks_signature(body, signature, key.as_bytes())
        }
    }
}

/// `POST /api/v1/{xero,quickbooks}/webhooks/{tenant_id}`.
///
/// The tenant is in the path, which is the shape the payment receivers
/// already use (`provider_webhook_handler`). MAPPS-1099 proposed a path
/// with no tenant in it, which forces the receiver to parse an unverified
/// body to find out whose key to verify with. Each tenant registers their
/// own provider app here, so each configures their own webhook URL, and
/// putting the tenant in the path means the signature is checked before a
/// single field of the body is believed.
///
/// Every outcome is recorded before the answer goes back (PMS-1182), so
/// "they never called", "we refused it" and "we took it and it matched
/// nothing" stay three distinguishable things. A delivery whose signature
/// did not verify records no event identifiers, for migration 213's
/// reason: unverified text must not reach an admin's screen as though the
/// provider had said it.
pub async fn invoice_issuer_webhook_handler(
    State(state): State<Arc<InvoiceIssuerWebhookState>>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let scoped = TenantId::from_trusted(tenant_id);
    let provider = state.provider;

    // No stored key is a 401 and no row: this endpoint is unauthenticated
    // by construction, so recording before a connection is known to exist
    // would let anyone who learns the URL write history into any tenant id
    // they can name. That is `provider_webhook_handler`'s rule and the
    // reasoning carries over unchanged.
    let key = match state.dispatcher.webhook_key(scoped, provider).await {
        Ok(Some(key)) if !key.trim().is_empty() => key,
        Ok(_) => return Err(AppError::Unauthorized),
        Err(_) => return Err(AppError::Unauthorized),
    };

    let Some(signature) = signature_header(provider, &headers) else {
        record(
            &state,
            tenant_id,
            "refused",
            None,
            Some("no signature header"),
        )
        .await;
        return Err(AppError::Unauthorized);
    };
    if !verify(provider, &body, signature, &key) {
        record(
            &state,
            tenant_id,
            "refused",
            None,
            Some("signature did not verify"),
        )
        .await;
        return Err(AppError::Unauthorized);
    }

    let result = apply(&state, scoped, &body).await;
    match &result {
        Ok(outcome) => record(&state, tenant_id, outcome.as_str(), None, None).await,
        Err(e) => record(&state, tenant_id, "failed", None, Some(&e.to_string())).await,
    }
    result.map(|_| StatusCode::OK)
}

/// What one delivery did, as `payment_webhook_deliveries.outcome` names it.
enum Outcome {
    /// At least one invoice moved.
    Accepted,
    /// Verified, and nothing to do: no invoice events, or none of them
    /// names an invoice this tenant holds, or the provider's state is one
    /// Mokosh does not mirror.
    Ignored,
    /// Verified, the invoice is ours, and the money could not be recorded.
    /// A human has to look; the provider retrying will not change it.
    Unreconciled,
}

impl Outcome {
    fn as_str(&self) -> &'static str {
        match self {
            Outcome::Accepted => "accepted",
            Outcome::Ignored => "ignored",
            Outcome::Unreconciled => "unreconciled",
        }
    }
}

async fn apply(
    state: &InvoiceIssuerWebhookState,
    tenant_id: TenantId,
    body: &[u8],
) -> AppResult<Outcome> {
    let provider = state.provider;
    let ids = invoice_ids(provider, body)?;
    let mut outcome = Outcome::Ignored;

    for external_id in ids {
        let Some(local) = state
            .billing
            .delegated_invoice(tenant_id, provider.as_str(), &external_id)
            .await?
        else {
            // A provider re-delivers, and it delivers events for invoices
            // this tenant created in the provider's own UI. Neither is an
            // error, and answering with one makes them retry forever.
            continue;
        };

        match state
            .dispatcher
            .external_status(tenant_id, provider, &external_id)
            .await?
        {
            ExternalInvoiceState::Paid => {
                // Nothing left to collect. A provider re-delivers, and the
                // second delivery of a paid invoice arrives against a
                // balance the first one already cleared: recording a zero
                // payment for it is refused by `payments_amount_positive`,
                // which is the column being right rather than this path
                // being unlucky. There is no money to record, so there is
                // nothing to do.
                if local.balance_due <= rust_decimal::Decimal::ZERO {
                    continue;
                }
                // The money went to the provider, so Mokosh records what
                // the provider collected and lets the one writer derive the
                // rest (PMS-953). `record_gateway_payment` is that path
                // already: it locks the invoice, refuses an overpayment,
                // is idempotent on the provider reference and recomputes.
                let recorded = state
                    .billing
                    .record_gateway_payment(
                        tenant_id,
                        provider.as_str(),
                        local.id,
                        &external_id,
                        local.balance_due,
                        &local.currency,
                        &serde_json::json!({
                            "source": "invoice_issuer_webhook",
                            "provider": provider.as_str(),
                            "external_invoice_id": external_id,
                        }),
                    )
                    .await?;
                outcome = if recorded {
                    Outcome::Accepted
                } else if matches!(outcome, Outcome::Ignored) {
                    // Already recorded by a prior delivery, or refused by a
                    // guard. The first is the common case and is not a
                    // problem; both are states a human can read off the
                    // delivery row rather than states to retry.
                    Outcome::Unreconciled
                } else {
                    outcome
                };
            }
            ExternalInvoiceState::Voided => {
                state
                    .billing
                    .void_delegated_invoice(tenant_id, local.id, provider.as_str())
                    .await?;
                outcome = Outcome::Accepted;
            }
            ExternalInvoiceState::Open => {}
        }
    }

    Ok(outcome)
}

/// PMS-1182's row, written on every path.
///
/// `payment_webhook_deliveries` rather than a table of its own: its
/// `provider` column records what the ROUTE names and is deliberately not
/// a foreign key, and the question this answers - did a delivery arrive,
/// and what did we do with it - is the same question for an invoice issuer
/// as for a gateway. A second table would be a second place to look for
/// one answer.
async fn record(
    state: &InvoiceIssuerWebhookState,
    tenant_id: Uuid,
    outcome: &str,
    invoice_id: Option<Uuid>,
    detail: Option<&str>,
) {
    state
        .billing
        .record_webhook_delivery(
            tenant_id,
            state.provider.as_str(),
            outcome,
            None,
            None,
            invoice_id,
            detail,
        )
        .await;
}
