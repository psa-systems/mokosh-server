//! Postgres-backed `BillingRepository`. Read-only surface +
//! create-trial-subscription for the org-create flow. See
//! `docs/mokosh-fixes/05-billing.md`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, BillingRepository, BillingTier, Subscription, SubscriptionStatus, TenantId,
};

use crate::conv::db_err;
use crate::pool::AuthPool;

pub struct PgBillingRepository {
    pool: AuthPool,
}

impl PgBillingRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct TierRow {
    tier_key: String,
    display_name: String,
    description: String,
    monthly_price_cents: i32,
    trial_days: i32,
    seat_count: i32,
    slot_limit: Option<i32>,
    sort_order: i32,
    features: Vec<String>,
    is_public: bool,
}

impl From<TierRow> for BillingTier {
    fn from(r: TierRow) -> Self {
        Self {
            tier_key: r.tier_key,
            display_name: r.display_name,
            description: r.description,
            monthly_price_cents: r.monthly_price_cents,
            trial_days: r.trial_days,
            seat_count: r.seat_count,
            slot_limit: r.slot_limit,
            sort_order: r.sort_order,
            features: r.features,
            is_public: r.is_public,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SubRow {
    tenant_id: uuid::Uuid,
    tier_key: String,
    status: String,
    trial_end: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
    grace_period_end: Option<DateTime<Utc>>,
}

impl TryFrom<SubRow> for Subscription {
    type Error = AuthError;
    fn try_from(r: SubRow) -> Result<Self, Self::Error> {
        Ok(Self {
            tenant_id: TenantId(r.tenant_id),
            tier_key: r.tier_key,
            status: SubscriptionStatus::parse(&r.status).ok_or_else(|| {
                AuthError::Storage(format!("invalid subscription status: {}", r.status))
            })?,
            trial_end: r.trial_end,
            current_period_end: r.current_period_end,
            cancel_at_period_end: r.cancel_at_period_end,
            grace_period_end: r.grace_period_end,
        })
    }
}

const SELECT_TIER: &str = r#"
    SELECT tier_key, display_name, description, monthly_price_cents,
           trial_days, seat_count, slot_limit, sort_order, features, is_public
    FROM mokosh_auth.billing_tiers
"#;

const SELECT_SUB: &str = r#"
    SELECT tenant_id, tier_key, status, trial_end, current_period_end,
           cancel_at_period_end, grace_period_end
    FROM mokosh_auth.subscriptions
"#;

#[async_trait]
impl BillingRepository for PgBillingRepository {
    async fn list_public_tiers(&self) -> Result<Vec<BillingTier>, AuthError> {
        let rows: Vec<TierRow> = sqlx::query_as(&format!(
            "{SELECT_TIER} WHERE is_public = TRUE ORDER BY sort_order ASC"
        ))
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(BillingTier::from).collect())
    }

    async fn find_tier(&self, tier_key: &str) -> Result<Option<BillingTier>, AuthError> {
        let row: Option<TierRow> = sqlx::query_as(&format!("{SELECT_TIER} WHERE tier_key = $1"))
            .bind(tier_key)
            .fetch_optional(self.pool.pg())
            .await
            .map_err(db_err)?;
        Ok(row.map(BillingTier::from))
    }

    async fn get_subscription(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<Subscription>, AuthError> {
        let row: Option<SubRow> = sqlx::query_as(&format!("{SELECT_SUB} WHERE tenant_id = $1"))
            .bind(tenant_id.0)
            .fetch_optional(self.pool.pg())
            .await
            .map_err(db_err)?;
        row.map(Subscription::try_from).transpose()
    }

    async fn create_trial(
        &self,
        tenant_id: TenantId,
        tier_key: &str,
        trial_days: i64,
    ) -> Result<Subscription, AuthError> {
        let trial_end = Utc::now() + chrono::Duration::days(trial_days.max(0));
        let row: SubRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.subscriptions
                (tenant_id, tier_key, status, trial_end)
             VALUES ($1, $2, 'trialing', $3)
             RETURNING tenant_id, tier_key, status, trial_end, current_period_end,
                       cancel_at_period_end, grace_period_end",
        )
        .bind(tenant_id.0)
        .bind(tier_key)
        .bind(trial_end)
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("subscription already exists for this tenant".into())
            }
            _ => db_err(e),
        })?;
        Subscription::try_from(row)
    }
}
