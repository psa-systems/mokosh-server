//! `/v1/billing/*` (public catalogue) + `/v1/orgs/:slug/billing` (per-org).
//!
//! Read-only surface. Stripe write integration (`checkout`, `cancel`,
//! `uncancel`) is deferred to a follow-up doc; those endpoints stay 404
//! today and the SPA's buttons surface them as disabled / Coming soon.
//!
//! See docs/mokosh-fixes/05-billing.md.

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, BillingTier, MembershipStatus, Subscription, SubscriptionStatus,
};
use serde::Serialize;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

// --- Wire shapes (match bunyip-web's api/billing.rs) --------------------

#[derive(Debug, Serialize)]
pub struct TierConfigView {
    pub tier_key: String,
    pub display_name: String,
    pub trial_days: u32,
    pub seat_count: u32,
    pub slot_limit: Option<u32>,
    pub sort_order: u32,
    pub monthly_price_cents: u32,
    pub features: Vec<String>,
}

impl From<BillingTier> for TierConfigView {
    fn from(t: BillingTier) -> Self {
        Self {
            tier_key: t.tier_key,
            display_name: t.display_name,
            trial_days: t.trial_days.max(0) as u32,
            seat_count: t.seat_count.max(0) as u32,
            slot_limit: t.slot_limit.map(|n| n.max(0) as u32),
            sort_order: t.sort_order.max(0) as u32,
            monthly_price_cents: t.monthly_price_cents.max(0) as u32,
            features: t.features,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SubscriptionView {
    pub tier_key: String,
    pub status: SubscriptionStatus,
    pub trial_end: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub grace_period_end: Option<DateTime<Utc>>,
}

impl From<Subscription> for SubscriptionView {
    fn from(s: Subscription) -> Self {
        Self {
            tier_key: s.tier_key,
            status: s.status,
            trial_end: s.trial_end,
            current_period_end: s.current_period_end,
            cancel_at_period_end: s.cancel_at_period_end,
            grace_period_end: s.grace_period_end,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BillingViewBody {
    pub subscription: Option<SubscriptionView>,
    pub tier: Option<TierConfigView>,
}

// --- Handlers -----------------------------------------------------------

/// GET /v1/billing/tiers - public, anonymous-OK.
pub async fn list_tiers(
    State(st): State<Arc<AuthHttpState>>,
) -> Result<Json<Vec<TierConfigView>>, HttpError> {
    let tiers = st.billing.list_public_tiers().await.map_err(HttpError)?;
    Ok(Json(tiers.into_iter().map(TierConfigView::from).collect()))
}

/// GET /v1/orgs/:slug/billing - admin-of-org gated.
pub async fn get_org_billing(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Path(slug): Path<String>,
) -> Result<Json<BillingViewBody>, HttpError> {
    let tenant = st
        .tenants
        .find_by_slug(&slug)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;

    let membership = st
        .memberships
        .find(caller.id, tenant.id)
        .await
        .map_err(HttpError)?
        .ok_or_else(|| HttpError(AuthError::NotFound))?;
    if !matches!(membership.status, MembershipStatus::Active) {
        return Err(HttpError(AuthError::Forbidden(
            "membership is suspended".into(),
        )));
    }
    if !membership.org_role.can_manage_members() {
        return Err(HttpError(AuthError::Forbidden(
            "owner or admin role required to view billing".into(),
        )));
    }

    let sub = st
        .billing
        .get_subscription(tenant.id)
        .await
        .map_err(HttpError)?;
    let tier = match &sub {
        Some(s) => st.billing.find_tier(&s.tier_key).await.map_err(HttpError)?,
        None => None,
    };

    Ok(Json(BillingViewBody {
        subscription: sub.map(SubscriptionView::from),
        tier: tier.map(TierConfigView::from),
    }))
}
