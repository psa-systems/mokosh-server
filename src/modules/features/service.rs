//! Reading and writing `feature_toggles` rows (PMS-1414).
//!
//! The registry is [`super::registry::Feature`]; this module only stores and
//! resolves states, and holds the process-wide snapshot every read path uses.
//!
//! ## Why a snapshot rather than a query per check
//!
//! A gate is checked on request paths, and a feature check that cost a round trip
//! would make gating a thing people avoid. So the state is loaded once at boot
//! into an `RwLock` and refreshed on an interval ([`super::job::FeatureToggleRefresh`]),
//! which is bunyip's shape and the same one `utils::email::SharedMailer` uses for
//! the live mailer.
//!
//! The cost is stated rather than hidden: a flip is visible to OTHER processes
//! within the refresh interval, not immediately. The process that served the
//! `PUT` swaps its own snapshot in the same handler, so the admin who flipped it
//! sees it at once; a sibling container does not. For a switch whose purpose is
//! "turn this on in staging and go look at it", a minute is not a problem worth
//! a cache-invalidation protocol.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::registry::{Feature, FeatureToggles};
use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::tenants::SYSTEM_TENANT_ID;
use crate::utils::error::{AppError, AppResult};

/// One stored row. `key` may name a feature this build does not know.
#[derive(Debug, Clone, sqlx::FromRow, PartialEq, Eq)]
pub struct FeatureToggleRow {
    pub key: String,
    pub enabled: bool,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// The process's view of which features are on.
///
/// `Default` is every feature off, which is also the state before the first load
/// finishes. Those agreeing is deliberate: a process that has not read the table
/// behaves like one with nothing switched on.
#[derive(Clone, Default)]
pub struct FeatureSnapshot(Arc<RwLock<FeatureToggles>>);

impl FeatureSnapshot {
    pub fn new(toggles: FeatureToggles) -> Self {
        Self(Arc::new(RwLock::new(toggles)))
    }

    /// Replace the snapshot. Takes effect on every consumer's next read.
    pub fn swap(&self, toggles: FeatureToggles) {
        *self
            .0
            .write()
            .expect("the feature-toggle lock is never held across a panic") = toggles;
    }

    /// The state as of now, cloned so no caller holds the lock across an await.
    pub fn current(&self) -> FeatureToggles {
        self.0
            .read()
            .expect("the feature-toggle lock is never held across a panic")
            .clone()
    }

    pub fn is_enabled(&self, feature: Feature) -> bool {
        self.current().is_enabled(feature)
    }
}

impl std::fmt::Debug for FeatureSnapshot {
    /// Names what is on. Safe to log: a feature key is not a secret, and which
    /// switches a deployment has flipped is exactly what a boot line should say.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeatureSnapshot")
            .field("on", &self.current().as_map())
            .finish()
    }
}

/// Every stored row, newest key order, including keys no variant matches.
///
/// SAFETY (PMS-285): `feature_toggles` is deployment-wide and carries no
/// `tenant_id`, so there is no RLS policy and no tenant GUC to set. The same
/// shape as `app_secrets` and `app_config`.
pub async fn all_rows(db: &Database) -> AppResult<Vec<FeatureToggleRow>> {
    sqlx::query_as::<_, FeatureToggleRow>(
        "SELECT key, enabled, updated_at, updated_by FROM feature_toggles ORDER BY key",
    )
    .fetch_all(db.migrator_pool())
    .await
    .map_err(|e| AppError::Database(format!("could not read feature_toggles: {e}")))
}

/// Read every row and resolve it against the registry.
pub async fn load(db: &Database) -> AppResult<FeatureToggles> {
    let rows = all_rows(db).await?;
    Ok(FeatureToggles::from_rows(
        rows.iter().map(|r| (r.key.as_str(), r.enabled)),
    ))
}

/// Flip one feature, audit it in the same transaction, and return the row.
///
/// The upsert and the audit row share a transaction because the pair is the
/// record: a flip nobody can attribute is the thing an admin page most needs to
/// avoid, and two statements outside a transaction can leave the switch moved
/// with no trace of who did it.
///
/// `feature` is a [`Feature`] rather than a string, so an unknown key cannot
/// reach here. The route is what turns a path segment into a variant and answers
/// 404 when it cannot.
pub async fn set(
    db: &Database,
    feature: Feature,
    enabled: bool,
    ctx: &AuditCtx,
) -> AppResult<FeatureToggleRow> {
    let before = all_rows(db)
        .await?
        .into_iter()
        .find(|row| row.key == feature.key())
        .map(|row| row.enabled)
        .unwrap_or(false);

    // SAFETY (PMS-285): deployment-wide write addressed to the system tenant,
    // the documented `from_trusted` case for an operator handler that is not
    // acting as a member of a tenant. The same shape as `settings::email`.
    let tenant = TenantId::from_trusted(SYSTEM_TENANT_ID);
    let mut tx = db.begin_with_tenant(tenant).await?;

    let row: FeatureToggleRow = sqlx::query_as(
        "INSERT INTO feature_toggles (key, enabled, updated_at, updated_by) \
         VALUES ($1, $2, NOW(), $3) \
         ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled, \
             updated_at = NOW(), updated_by = EXCLUDED.updated_by \
         RETURNING key, enabled, updated_at, updated_by",
    )
    .bind(feature.key())
    .bind(enabled)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::Database(format!("could not write the feature toggle: {e}")))?;

    audit_write(
        &mut *tx,
        tenant,
        ctx,
        AuditAction::Update,
        "feature_toggles",
        None,
        Some(serde_json::json!({ "key": feature.key(), "enabled": before })),
        Some(serde_json::json!({
            "event": "feature_toggle.set",
            "key": feature.key(),
            "enabled": enabled,
            "issue": feature.issue(),
        })),
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        key = feature.key(),
        enabled,
        was = before,
        "feature toggle set"
    );
    Ok(row)
}
