//! DB-backed product name (PMS-789).
//!
//! Scope follows the PMS-636 decision the email settings already took: one
//! SYSTEM value stored on the default tenant (`Uuid::from_u128(1)`), not one
//! per tenant. "This deployment is psa.systems" is a property of the box, and
//! the loudest consumer - the catch-all 404 page - is unauthenticated and has
//! no tenant to scope a lookup to.
//!
//! `tenant_settings` is fail-closed RLS (migration 038), so every access goes
//! through `begin_with_tenant(SYSTEM_TENANT)`; a raw pool query would be
//! filtered to nothing. That is also why this needs no migration of its own -
//! the row lives in the table PMS-638 already writes.
//!
//! Reads at use time come from [`crate::utils::app_name::app_name`], not from
//! here. This module owns the store and keeps that cache current.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Database;
use crate::utils::app_name::{app_name, sanitize, set_app_name, DEFAULT_APP_NAME};
use crate::utils::error::{AppError, AppResult};

/// System tenant that owns the single deployment-wide value. Matches
/// `settings::email`'s `system_tenant` and `auth::bootstrap`'s
/// `default_tenant_id`.
fn system_tenant() -> Uuid {
    Uuid::from_u128(1)
}

const APP_NAME_CATEGORY: &str = "system";
const APP_NAME_KEY: &str = "app_name";

/// Admin write payload for `PUT /settings/app-name`. An empty string clears
/// the override and restores [`DEFAULT_APP_NAME`], mirroring how the email
/// settings treat an empty text field.
#[derive(Debug, Deserialize)]
pub struct AppNameInput {
    pub app_name: String,
}

/// Read view for `GET /settings/app-name`.
///
/// `app_name` is `None` when no operator has set one; `effective` is what
/// consumers actually render. Reporting only the first would leave the admin
/// UI showing an empty box next to mail that says "Mokosh", and reporting only
/// the second would hide whether the value is configured or defaulted.
#[derive(Debug, Serialize)]
pub struct AppNameView {
    pub app_name: Option<String>,
    pub effective: String,
    pub default: &'static str,
}

impl AppNameView {
    fn from_stored(stored: Option<String>) -> Self {
        Self {
            effective: stored
                .clone()
                .unwrap_or_else(|| DEFAULT_APP_NAME.to_string()),
            app_name: stored,
            default: DEFAULT_APP_NAME,
        }
    }
}

/// Read the stored name for the system tenant, if present.
async fn load_stored(db: &Database) -> AppResult<Option<String>> {
    let mut tx = db.begin_with_tenant(system_tenant()).await?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM tenant_settings WHERE tenant_id = $1 AND category = $2 AND key = $3",
    )
    .bind(system_tenant())
    .bind(APP_NAME_CATEGORY)
    .bind(APP_NAME_KEY)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(value.and_then(|v| v.as_str().map(str::to_string)))
}

/// Load the stored name into the process cache. Called at boot and after every
/// write.
///
/// A stored value that no longer satisfies [`sanitize`] is dropped with a
/// warning rather than rendered: the row could predate a rule or have been
/// edited straight in the database, and a control character in it would reach
/// an email `Subject` header. Dropping it falls back to the default, which is
/// the same posture as having no row.
pub async fn resolve_and_cache(db: &Database) -> AppResult<()> {
    let stored = load_stored(db).await?;
    let usable = stored.and_then(|raw| match sanitize(&raw) {
        Ok(clean) => Some(clean),
        Err(reason) => {
            tracing::warn!(
                stored = %raw,
                reason = %reason,
                "stored app name is unusable; falling back to the default"
            );
            None
        }
    });
    set_app_name(usable.as_deref());
    Ok(())
}

/// Current stored name plus what consumers render for it.
pub async fn get_app_name_settings(db: &Database) -> AppResult<AppNameView> {
    Ok(AppNameView::from_stored(load_stored(db).await?))
}

/// Persist the name for the system tenant and refresh the cache, so the change
/// takes effect on the next mail sent and the next 404 rendered, with no
/// restart.
pub async fn put_app_name_settings(db: &Database, input: AppNameInput) -> AppResult<AppNameView> {
    // An explicit empty string is "clear the override", not "render nothing".
    let stored: Option<String> = if input.app_name.trim().is_empty() {
        None
    } else {
        Some(sanitize(&input.app_name).map_err(|e| AppError::validation_field("app_name", &e))?)
    };

    let mut tx = db.begin_with_tenant(system_tenant()).await?;
    match &stored {
        Some(name) => {
            sqlx::query(
                "INSERT INTO tenant_settings (tenant_id, category, key, value)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant_id, category, key)
                 DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
            )
            .bind(system_tenant())
            .bind(APP_NAME_CATEGORY)
            .bind(APP_NAME_KEY)
            .bind(serde_json::Value::String(name.clone()))
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query(
                "DELETE FROM tenant_settings
                 WHERE tenant_id = $1 AND category = $2 AND key = $3",
            )
            .bind(system_tenant())
            .bind(APP_NAME_CATEGORY)
            .bind(APP_NAME_KEY)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;

    set_app_name(stored.as_deref());
    debug_assert_eq!(
        &*app_name(),
        AppNameView::from_stored(stored.clone()).effective
    );
    Ok(AppNameView::from_stored(stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read view has to answer both questions an admin screen asks: is a
    /// name configured, and what is being rendered right now.
    #[test]
    fn the_view_separates_the_stored_name_from_the_effective_one() {
        let unset = AppNameView::from_stored(None);
        assert_eq!(unset.app_name, None);
        assert_eq!(unset.effective, DEFAULT_APP_NAME);

        let set = AppNameView::from_stored(Some("PSA Systems".to_string()));
        assert_eq!(set.app_name.as_deref(), Some("PSA Systems"));
        assert_eq!(set.effective, "PSA Systems");
    }
}
