//! Settings service.

use crate::modules::auth::TenantId;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

#[derive(Clone)]
pub struct SettingsService {
    db: Database,
}

impl SettingsService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // PMS-115 tenant settings -------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_tenant_settings(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TenantSettingResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenant_settings WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, SettingRow>(
            r#"SELECT id, category, key, value FROM tenant_settings
               WHERE tenant_id = $1
               ORDER BY category, key
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Upsert a single tenant setting from a request DTO. PMS-198: this
    /// is a thin wrapper over [`put_setting`](Self::put_setting), the
    /// single canonical `INSERT ... ON CONFLICT` for `tenant_settings`,
    /// so the SQL is not duplicated across the two call sites.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_tenant_setting(
        &self,
        tenant_id: TenantId,
        request: &UpsertTenantSettingRequest,
    ) -> AppResult<TenantSettingResponse> {
        self.put_setting(
            tenant_id,
            &request.category,
            &request.key,
            request.value.clone(),
        )
        .await
    }

    // Category- and key-scoped tenant_settings access (PMS-113 AC1) ----------

    /// List every setting for `tenant_id` in `category`. The endpoint
    /// is paginated only by limit/offset on the data tier (settings
    /// per category are small); no Paginated envelope here because
    /// the SPA wants the full category snapshot on the settings page.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_settings_by_category(
        &self,
        tenant_id: TenantId,
        category: &str,
    ) -> AppResult<Vec<TenantSettingResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, SettingRow>(
            r#"SELECT id, category, key, value FROM tenant_settings
               WHERE tenant_id = $1 AND category = $2
               ORDER BY key"#,
        )
        .bind(tenant_id)
        .bind(category)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_setting(
        &self,
        tenant_id: TenantId,
        category: &str,
        key: &str,
    ) -> AppResult<TenantSettingResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, SettingRow>(
            r#"SELECT id, category, key, value FROM tenant_settings
               WHERE tenant_id = $1 AND category = $2 AND key = $3"#,
        )
        .bind(tenant_id)
        .bind(category)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Tenant setting".to_string()))?;
        Ok(row.into())
    }

    /// Upsert a single (category, key) value. Caller is expected to
    /// have already run `validate_setting_value` against `value`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn put_setting(
        &self,
        tenant_id: TenantId,
        category: &str,
        key: &str,
        value: serde_json::Value,
    ) -> AppResult<TenantSettingResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO tenant_settings (tenant_id, category, key, value)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, category, key) DO UPDATE SET
                 value = EXCLUDED.value, updated_at = NOW()
               RETURNING id"#,
        )
        .bind(tenant_id)
        .bind(category)
        .bind(key)
        .bind(&value)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(TenantSettingResponse {
            id,
            category: category.to_string(),
            key: key.to_string(),
            value,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_setting_by_key(
        &self,
        tenant_id: TenantId,
        category: &str,
        key: &str,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            "DELETE FROM tenant_settings WHERE tenant_id = $1 AND category = $2 AND key = $3",
        )
        .bind(tenant_id)
        .bind(category)
        .bind(key)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(AppError::NotFound("Tenant setting".to_string()));
        }
        Ok(())
    }

    // PMS-113 AC2: this service is now the single canonical writer for
    // `module_config`. The `/api/v1/settings/modules/*` routes hit it
    // directly; the `/api/v1/tenants/:id/modules/:module` routes from
    // PMS-21 delegate to it (no more duplicate SQL in TenantService).
    // ----------------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_module_configs(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ModuleConfigResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM module_config WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, ModCfgRow>(
            r#"SELECT id, module_name, is_enabled, config FROM module_config
               WHERE tenant_id = $1
               ORDER BY module_name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Read a module's config. PMS-113 AC4: returns a soft default
    /// (`is_enabled: false`, `config: {}`) when no row exists rather
    /// than `NotFound`, so the SPA always gets a shape-compatible
    /// response and a "this module hasn't been touched yet" tenant
    /// reads consistently across both API surfaces.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_module_config(
        &self,
        tenant_id: TenantId,
        module: &str,
    ) -> AppResult<ModuleConfigResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ModCfgRow>(
            r#"SELECT id, module_name, is_enabled, config FROM module_config
               WHERE tenant_id = $1 AND module_name = $2"#,
        )
        .bind(tenant_id)
        .bind(module)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(row
            .map(Into::into)
            .unwrap_or_else(|| ModuleConfigResponse::default_for(module)))
    }

    /// Read just the `is_enabled` flag, fast path used by
    /// `RequireModuleEnabled` (PMS-113 AC3). Missing row -> `false`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn is_module_enabled(&self, tenant_id: TenantId, module: &str) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let enabled: Option<bool> = sqlx::query_scalar(
            r#"SELECT COALESCE(is_enabled, FALSE) FROM module_config
               WHERE tenant_id = $1 AND module_name = $2"#,
        )
        .bind(tenant_id)
        .bind(module)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(enabled.unwrap_or(false))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_module_config(
        &self,
        tenant_id: TenantId,
        module: &str,
        request: &UpsertModuleConfigRequest,
    ) -> AppResult<ModuleConfigResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO module_config (tenant_id, module_name, is_enabled, config)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, module_name) DO UPDATE SET
                 is_enabled = EXCLUDED.is_enabled,
                 config = EXCLUDED.config,
                 updated_at = NOW()
               RETURNING id"#,
        )
        .bind(tenant_id)
        .bind(module)
        .bind(request.is_enabled)
        .bind(&request.config)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ModuleConfigResponse {
            id: Some(id),
            module_name: module.to_string(),
            is_enabled: request.is_enabled,
            config: request.config.clone(),
        })
    }
}

#[derive(sqlx::FromRow)]
struct SettingRow {
    id: Uuid,
    category: String,
    key: String,
    value: serde_json::Value,
}

impl From<SettingRow> for TenantSettingResponse {
    fn from(r: SettingRow) -> Self {
        Self {
            id: r.id,
            category: r.category,
            key: r.key,
            value: r.value,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ModCfgRow {
    id: Uuid,
    module_name: String,
    is_enabled: Option<bool>,
    config: serde_json::Value,
}

impl From<ModCfgRow> for ModuleConfigResponse {
    fn from(r: ModCfgRow) -> Self {
        Self {
            id: Some(r.id),
            module_name: r.module_name,
            is_enabled: r.is_enabled.unwrap_or(false),
            config: r.config,
        }
    }
}

/// Read the tenant-wide standard-due-date offset in business days
/// (`scheduling/default_due_business_days`), or `0` when unset (PMS-345). `0`
/// means "no default due date". Free function so the projects and tickets
/// services can apply the default without taking a dependency on
/// `SettingsService`.
pub async fn read_default_due_business_days(db: &Database, tenant_id: TenantId) -> AppResult<u32> {
    let mut tx = db.begin_with_tenant(tenant_id).await?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT value FROM tenant_settings
           WHERE tenant_id = $1 AND category = 'scheduling' AND key = 'default_due_business_days'"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(value
        .and_then(|v| v.as_u64())
        .map(|n| n.min(365) as u32)
        .unwrap_or(0))
}

/// Read the tenant-wide per-day cap on a user's logged time, in minutes
/// (`time_tracking/max_hours_per_day`), defaulting to `24 * 60` when unset
/// (PMS-396). The stored value is whole hours in `1..=24` (enforced by
/// `validate_setting_value`); this clamps defensively in case a row was written
/// before validation existed. Free function so `TimeTrackingService` can read
/// the cap without a dependency on `SettingsService`.
pub async fn read_max_minutes_per_day(db: &Database, tenant_id: TenantId) -> AppResult<i32> {
    let mut tx = db.begin_with_tenant(tenant_id).await?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT value FROM tenant_settings
           WHERE tenant_id = $1 AND category = 'time_tracking' AND key = 'max_hours_per_day'"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let hours = value
        .and_then(|v| v.as_u64())
        .map(|n| n.clamp(1, 24))
        .unwrap_or(24);
    Ok((hours as i32) * 60)
}

/// PMS-1030: the zone a tenant's day happens in, for the jobs that have no
/// user to ask: the default `business_hours` row's `timezone`, else `UTC`.
///
/// Not a new `tenants.timezone` column: the SLA's business hours already
/// hold the zone this MSP's day happens in, and a second home for it is how
/// the two would come to disagree. Migration 049 keeps the default to one
/// row per tenant. Takes a connection rather than the pool because the
/// contract sweep reads it on the migrator pool, across tenants.
pub async fn read_tenant_zone(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
) -> AppResult<String> {
    let zone: Option<String> = sqlx::query_scalar(
        r#"SELECT timezone FROM business_hours
           WHERE tenant_id = $1 AND is_default = TRUE
           ORDER BY created_at, id
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(zone.unwrap_or_else(|| "UTC".to_string()))
}

/// PMS-943: does this employer track breaks (`timesheets/track_breaks`)?
///
/// Tenant-level rather than per company: the employee taking the break is the
/// MSP's, and a client company has none of the MSP's staff, so a per-company
/// setting would be keyed on the wrong entity. Unset means off, so an employer
/// that has never thought about it is not asked to.
pub async fn read_track_breaks(db: &Database, tenant_id: TenantId) -> AppResult<bool> {
    let mut tx = db.begin_with_tenant(tenant_id).await?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT value FROM tenant_settings
           WHERE tenant_id = $1 AND category = 'timesheets' AND key = 'track_breaks'"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(value.and_then(|v| v.as_bool()).unwrap_or(false))
}

/// PMS-1028: the currency an invoice is issued in when nothing names one
/// (`billing_prefs/currency`, a 3-letter ISO 4217 code the settings route
/// validates). Unset means `USD`, which is what every writer hardcoded
/// before, so nothing moves for a tenant that configured nothing.
///
/// Takes the caller's tenant-GUC connection rather than the pool: the three
/// invoice writers and the credit note read it inside the transaction that
/// inserts the row, and `tenant_settings` is RLS-covered.
pub async fn read_default_currency(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
) -> AppResult<String> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT value FROM tenant_settings
           WHERE tenant_id = $1 AND category = 'billing_prefs' AND key = 'currency'"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(value
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "USD".to_string()))
}

/// PMS-469: read the fallback `companies.id` that the email-intake
/// service should use when auto-creating contacts for unknown
/// senders. `Ok(None)` when unset (or malformed) - the caller treats
/// that as "preserve the Phase 1 422-on-unknown-sender posture".
/// Reads off a `PgPool` so the email-intake flow does not have to
/// thread its outer connection through.
pub async fn read_email_intake_default_company(
    // PMS-692: takes the tenant-GUC transaction connection (like
    // `read_ci_impact_max_depth`), not a bare pool - `tenant_settings` is
    // RLS-covered, so a bare-pool read fail-closes on the NOBYPASSRLS connection.
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
) -> AppResult<Option<Uuid>> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT value FROM tenant_settings
           WHERE tenant_id = $1 AND category = 'email_intake' AND key = 'default_company_id'"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(value
        .and_then(|v| v.as_str().map(str::to_string))
        .and_then(|s| Uuid::parse_str(&s).ok()))
}

/// PMS-475: read the per-tenant ceiling for the CI impact-graph
/// traversal (`ci/impact_max_depth`). Defaults to 5 when the row is
/// absent; clamps to 1..=10 defensively so a row that predates the
/// validator cannot blow the query plan. The route handler applies
/// the caller-supplied `depth` query param as a separate upper
/// bound, so the effective walk depth is
/// `min(query_depth, this_setting, hard_ceiling)`.
pub async fn read_ci_impact_max_depth(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
) -> AppResult<u32> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT value FROM tenant_settings
           WHERE tenant_id = $1 AND category = 'ci' AND key = 'impact_max_depth'"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(value
        .and_then(|v| v.as_u64())
        .map(|n| n.clamp(1, 10) as u32)
        .unwrap_or(5))
}

/// Read the per-tenant cycle cap for mutating workflow rules on
/// transition triggers (`workflows/rule_max_depth`, PMS-467). Defaults
/// to 3 when the row is absent; clamps to 1..=10 defensively in case a
/// row predates the validator. Takes a raw `PgConnection` so the
/// workflow executor can read it from inside its own transaction
/// without nesting a second `begin_with_tenant` (which would deadlock
/// on the `app.current_tenant` GUC SET).
pub async fn read_workflow_rule_max_depth(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
) -> AppResult<u32> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        r#"SELECT value FROM tenant_settings
           WHERE tenant_id = $1 AND category = 'workflows' AND key = 'rule_max_depth'"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(value
        .and_then(|v| v.as_u64())
        .map(|n| n.clamp(1, 10) as u32)
        .unwrap_or(3))
}
