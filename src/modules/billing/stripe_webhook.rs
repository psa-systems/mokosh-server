//! PMS-711: inbound Stripe webhook receiver.
//!
//! Route: `POST /api/v1/stripe/webhooks/{tenant_id}`. Mounted OUTSIDE the JWT
//! auth chain (mirrors `auth::bunyip_webhook`): the request is from Stripe, not
//! a mokosh session, and authenticates itself with the `Stripe-Signature`
//! header - an HMAC over the raw body keyed by the tenant's per-account webhook
//! secret.
//!
//! Why the tenant id is in the URL: the signing secret is per-tenant (each MSP
//! connects their own Stripe account), so the receiver must know WHICH secret
//! to verify against before it can trust anything in the body. The path segment
//! selects the tenant; it is not itself a credential - the signature is. The
//! tenant configures this exact URL in their Stripe dashboard.
//!
//! Order is load-bearing (same as the bunyip receiver): select the tenant's
//! provider, verify the signature over the RAW bytes, and only then parse. An
//! unverified body never reaches business logic. Reconciliation is idempotent
//! at the DB layer (unique provider references), so Stripe's retries are safe.

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

/// Stripe's signature header name.
const SIGNATURE_HEADER: &str = "Stripe-Signature";

/// State for the Stripe webhook receiver. Holds the `BillingService` (which
/// owns the DB handle, encryption key, and HTTP client) so the handler can load
/// the tenant's signing secret and reconcile payments in one place.
#[derive(Clone)]
pub struct StripeWebhookState {
    pub billing: Arc<BillingService>,
}

/// Handler for `POST /api/v1/stripe/webhooks/{tenant_id}`.
pub async fn stripe_webhook_handler(
    State(state): State<Arc<StripeWebhookState>>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    // 1. Signature header. Missing / non-ASCII = 401 (do not parse the body).
    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    // 2. Select the tenant's active Stripe provider (decrypts its signing
    //    secret). No active gateway = 401: nothing to verify against, and we do
    //    not confirm whether the tenant otherwise exists.
    let provider = state
        .billing
        .provider_for_webhook(tenant_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // 3. Verify over the RAW bytes, then parse. `verify_and_parse_webhook`
    //    returns Unauthorized on a bad signature before it touches the JSON.
    let event = provider.verify_and_parse_webhook(&body, signature)?;

    // 4. Dispatch. SAFETY (PMS-285 / PMS-711): the path `tenant_id` is trusted
    //    only now - the signature verified against THIS tenant's secret, so the
    //    caller has proven possession of that tenant's Stripe credential.
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
        PaymentEvent::Ignored { kind } => {
            tracing::debug!(
                target: "mokosh_server.billing",
                %kind,
                "stripe webhook event ignored"
            );
        }
    }

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))))
}
