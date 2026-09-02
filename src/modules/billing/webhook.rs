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
    let provider = state
        .billing
        .provider_for_webhook(tenant_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if provider.id() != state.provider_id {
        return Err(AppError::Unauthorized);
    }

    // 2. Verify over the RAW bytes, then parse. The provider picks its own
    //    headers out of the map and returns Unauthorized on a missing or bad
    //    signature before it touches the JSON.
    let event = provider.verify_and_parse_webhook(&body, &headers).await?;

    // 3. Dispatch. SAFETY (PMS-285 / PMS-711): the path `tenant_id` is trusted
    //    only now - verification ran against THIS tenant's credential, so the
    //    caller has proven possession of it.
    //    `from_trusted` bridges it to the tenant-scoped service calls, which set
    //    the `app.current_tenant` GUC via `begin_with_tenant`.
    let scoped = TenantId::from_trusted(tenant_id);
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
        }
    }

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))))
}
