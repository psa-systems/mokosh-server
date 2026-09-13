//! PMS-711 / PMS-969: inbound payment-provider webhook receiver.
//!
//! One handler serves every provider, mounted once per provider at
//! `POST /api/v1/{provider}/webhooks/{tenant_id}`, OUTSIDE the JWT auth chain
//! (mirrors `auth::bunyip_webhook`): the request is from the provider, not a
//! mokosh session, and authenticates itself the way that provider signs - a
//! `Stripe-Signature` HMAC over the raw body, or PayPal's five transmission
//! headers checked back with PayPal. The receiver does not know which; it hands
//! the header map to the tenant's provider and lets it decide.
//!
//! Why the tenant id is in the URL: the signing material is per-tenant (each
//! MSP connects their own account), so the receiver must know WHICH tenant's
//! credential to verify against before it can trust anything in the body. The
//! path segment selects the tenant; it is not itself a credential - the
//! verification is. The tenant configures this exact URL in their provider's
//! dashboard.
//!
//! Why the provider is in the URL too: `provider_for_webhook` resolves the
//! tenant's ACTIVE gateway, and a delivery from a provider the tenant has since
//! switched away from would otherwise be handed to the wrong verifier. The
//! resolved provider must be the one the route names, or the request is
//! refused as unauthenticated - which is what it is, since nothing the tenant
//! currently trusts signed it.
//!
//! Order is load-bearing (same as the bunyip receiver): select the tenant's
//! provider, check it is the one this route is for, verify over the RAW bytes,
//! and only then parse. An unverified body never reaches business logic.
//! Reconciliation is idempotent at the DB layer (unique provider references),
//! so a provider's retries are safe.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use super::provider::PaymentEvent;
use super::BillingService;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

/// State for one provider's webhook receiver. Holds the `BillingService`
/// (which owns the DB handle, encryption key, and HTTP client) so the handler
/// can load the tenant's credential and reconcile payments in one place, plus
/// the provider discriminator this mount serves.
#[derive(Clone)]
pub struct ProviderWebhookState {
    pub billing: Arc<BillingService>,
    /// Matches `PaymentProvider::id` and the stored `provider` column.
    pub provider_id: &'static str,
}

/// Handler for `POST /api/v1/{provider}/webhooks/{tenant_id}`.
///
/// PMS-1182: whatever happens below, the delivery is recorded before the
/// answer goes back. That wrapper is the point: every path through `dispatch`
/// ends in a `?`, so a refused delivery used to leave this process with no
/// trace of having received anything, and "they never called", "we refused it"
/// and "we took it and it matched no invoice" were one indistinguishable
/// symptom - the customer paid and the invoice is still outstanding.
pub async fn provider_webhook_handler(
    State(state): State<Arc<ProviderWebhookState>>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    // 1. Select the tenant's active provider (recovers its credential). No
    //    active gateway = 401: nothing to verify against, and we do not confirm
    //    whether the tenant otherwise exists. The wrong provider for this route
    //    is the same 401, for the reason in the module doc.
    //
    //    PMS-1182: and no row. This endpoint is unauthenticated by
    //    construction, so recording before a gateway is known to exist would
    //    let anyone who learns the URL write history into any tenant id they
    //    can name. A gateway that exists and cannot be BUILT is a different
    //    thing and is recorded, because that is a real delivery arriving at a
    //    broken configuration and the admin needs to know it happened.
    let resolved = state
        .billing
        .provider_for_webhook(tenant_id, state.provider_id)
        .await;
    let provider = match resolved {
        Ok(Some(provider)) => provider,
        Ok(None) => return Err(AppError::Unauthorized),
        Err(e) => {
            record(&state, tenant_id, "failed", None, Some(&e.to_string())).await;
            return Err(e);
        }
    };
    // PMS-1179: the lookup above is BY this route's provider, so a mismatch
    // cannot reach here. Kept as a belt: it costs one comparison and it is the
    // invariant the verification below depends on.
    if provider.id() != state.provider_id {
        return Err(AppError::Unauthorized);
    }

    let result = dispatch(&state, provider, tenant_id, &headers, &body).await;
    match &result {
        Ok(handled) => {
            record(&state, tenant_id, handled.outcome, Some(handled), None).await;
        }
        Err(e) => {
            // `refused` and `failed` are told apart by what the error IS. An
            // Unauthorized is a signature this deployment would not accept,
            // which is the admin's to fix; anything else is our own failure to
            // handle a delivery that may well have been genuine, and the
            // provider will retry it. Only the first is a configuration
            // problem, so they must not read the same.
            let outcome = if matches!(e, AppError::Unauthorized) {
                "refused"
            } else {
                "failed"
            };
            record(&state, tenant_id, outcome, None, Some(&e.to_string())).await;
        }
    }
    result.map(|handled| handled.response)
}

/// PMS-1182: write the row, with the event's own identity when there is one.
///
/// `handled` is `None` for every failure path, and that is not an omission:
/// `event_type` and `event_id` would have to come out of a body whose
/// signature did not verify, and this table must not become the place where
/// attacker-supplied text is shown to an admin as though the provider had said
/// it (migration 213).
async fn record(
    state: &ProviderWebhookState,
    tenant_id: Uuid,
    outcome: &str,
    handled: Option<&Handled>,
    detail: Option<&str>,
) {
    state
        .billing
        .record_webhook_delivery(
            tenant_id,
            state.provider_id,
            outcome,
            handled.and_then(|h| h.event_type.as_deref()),
            handled.and_then(|h| h.event_id.as_deref()),
            handled.and_then(|h| h.invoice_id),
            detail,
        )
        .await;
}

/// One handled delivery: the answer to send, and what to record about it.
struct Handled {
    response: (StatusCode, Json<serde_json::Value>),
    outcome: &'static str,
    event_type: Option<String>,
    event_id: Option<String>,
    invoice_id: Option<Uuid>,
}

/// PMS-1182: the provider's own event type and id, read off a body that has
/// already verified.
///
/// Read here rather than carried on `PaymentEvent`, because that enum models
/// what an event MEANS to this application and every provider's own naming
/// stays outside it. `event_type` is PayPal's key and `type` is Stripe's; both
/// call the id `id`, which is what their dashboards key their own logs on, so
/// it is the one field that lets an admin find the same delivery on their
/// side.
fn identify(raw: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return (None, None);
    };
    let text = |v: &serde_json::Value| v.as_str().map(str::to_string);
    let event_type = text(&value["event_type"]).or_else(|| text(&value["type"]));
    (event_type, text(&value["id"]))
}

async fn dispatch(
    state: &ProviderWebhookState,
    provider: Box<dyn crate::modules::billing::provider::PaymentProvider>,
    tenant_id: Uuid,
    headers: &HeaderMap,
    body: &Bytes,
) -> AppResult<Handled> {
    // 2. Verify over the RAW bytes, then parse. The provider picks its own
    //    headers out of the map and returns Unauthorized on a missing or bad
    //    signature before it touches the JSON.
    let event = provider.verify_and_parse_webhook(body, headers).await?;

    // 3. Dispatch. SAFETY (PMS-285 / PMS-711): the path `tenant_id` is trusted
    //    only now - verification ran against THIS tenant's credential, so the
    //    caller has proven possession of it.
    //    `from_trusted` bridges it to the tenant-scoped service calls, which set
    //    the `app.current_tenant` GUC via `begin_with_tenant`.
    let scoped = TenantId::from_trusted(tenant_id);
    // PMS-1182: the body verified, so its own identifiers can be read and
    // shown to an admin as the provider's words.
    let (event_type, event_id) = identify(body);
    let mut invoice = None;
    let mut outcome = "accepted";
    match event {
        PaymentEvent::PaymentSucceeded {
            provider_reference,
            tenant_id: event_tenant,
            invoice_id,
            amount,
            currency,
            raw,
        } => {
            // Defence in depth: the metadata tenant must match the URL tenant
            // whose secret just verified. A mismatch means a session created for
            // a different tenant landed on this endpoint; refuse it.
            if event_tenant != tenant_id {
                return Err(AppError::Unauthorized);
            }
            state
                .billing
                .record_gateway_payment(
                    scoped,
                    invoice_id,
                    &provider_reference,
                    amount,
                    &currency,
                    &raw,
                )
                .await?;
            invoice = Some(invoice_id);
        }
        PaymentEvent::Refunded {
            provider_reference,
            currency,
            refunds,
            raw,
        } => {
            state
                .billing
                .record_gateway_refunds(scoped, &provider_reference, &currency, &refunds, &raw)
                .await?;
        }
        PaymentEvent::RequiresCapture { order_id } => {
            // The buyer approved; charge them. The provider's completed-capture
            // event follows and records the payment, so nothing is written
            // here, and a capture that fails is a 500 so the provider retries
            // the approval delivery.
            provider.capture(&order_id).await?;
        }
        PaymentEvent::Ignored { kind } => {
            tracing::debug!(
                target: "mokosh_server.billing",
                %kind,
                provider = state.provider_id,
                "webhook event ignored"
            );
            // Recorded as its own outcome rather than as accepted: an event
            // this build does not act on is a normal thing to receive, and an
            // admin reading the list has to be able to tell it from a payment
            // that landed.
            outcome = "ignored";
        }
    }

    Ok(Handled {
        response: (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        outcome,
        event_type,
        event_id,
        invoice_id: invoice,
    })
}

/// PMS-1182: the provider's own naming of a delivery.
#[cfg(test)]
mod tests {
    use super::identify;

    /// PayPal keys the type on `event_type` and Stripe on `type`, and both
    /// call the id `id`. The id is what their own dashboards key their logs
    /// on, so it is the field that lets an admin line up our record with
    /// theirs.
    #[test]
    fn each_provider_is_named_the_way_it_names_itself() {
        let paypal = br#"{"id":"WH-862927803B332090X","event_type":"CHECKOUT.ORDER.APPROVED"}"#;
        assert_eq!(
            identify(paypal),
            (
                Some("CHECKOUT.ORDER.APPROVED".to_string()),
                Some("WH-862927803B332090X".to_string())
            )
        );

        let stripe = br#"{"id":"evt_1234","type":"checkout.session.completed"}"#;
        assert_eq!(
            identify(stripe),
            (
                Some("checkout.session.completed".to_string()),
                Some("evt_1234".to_string())
            )
        );
    }

    /// A body that names neither, or is not JSON at all, records the delivery
    /// with no identifiers rather than failing it. The row exists to say a
    /// delivery arrived; it must not be the thing that stops one being
    /// handled.
    #[test]
    fn a_body_that_names_nothing_is_still_a_recordable_delivery() {
        assert_eq!(identify(b"{}"), (None, None));
        assert_eq!(identify(b"not json at all"), (None, None));
        // A non-string id is not coerced: showing `12` where the provider
        // shows `evt_...` would be worse than showing nothing.
        assert_eq!(identify(br#"{"id":12,"type":true}"#), (None, None));
    }
}
