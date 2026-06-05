//! Settings service.

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
        tenant_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TenantSettingResponse>, u64)> {
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenant_settings WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
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
        .fetch_all(self.db.pool())
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_tenant_setting(
        &self,
        tenant_id: Uuid,
        request: &UpsertTenantSettingRequest,
    ) -> AppResult<TenantSettingResponse> {
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO tenant_settings (tenant_id, category, key, value)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, category, key) DO UPDATE SET
                 value = EXCLUDED.value, updated_at = NOW()
               RETURNING id"#,
        )
        .bind(tenant_id)
        .bind(&request.category)
        .bind(&request.key)
        .bind(&request.value)
        .fetch_one(self.db.pool())
        .await?;
        Ok(TenantSettingResponse {
            id,
            category: request.category.clone(),
            key: request.key.clone(),
            value: request.value.clone(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_tenant_setting(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let n = sqlx::query("DELETE FROM tenant_settings WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("TenantSetting".to_string()));
        }
        Ok(())
    }

    // Category- and key-scoped tenant_settings access (PMS-113 AC1) ----------

    /// List every setting for `tenant_id` in `category`. The endpoint
    /// is paginated only by limit/offset on the data tier (settings
    /// per category are small); no Paginated envelope here because
    /// the SPA wants the full category snapshot on the settings page.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_settings_by_category(
        &self,
        tenant_id: Uuid,
        category: &str,
    ) -> AppResult<Vec<TenantSettingResponse>> {
        let rows = sqlx::query_as::<_, SettingRow>(
            r#"SELECT id, category, key, value FROM tenant_settings
               WHERE tenant_id = $1 AND category = $2
               ORDER BY key"#,
        )
        .bind(tenant_id)
        .bind(category)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_setting(
        &self,
        tenant_id: Uuid,
        category: &str,
        key: &str,
    ) -> AppResult<TenantSettingResponse> {
        let row = sqlx::query_as::<_, SettingRow>(
            r#"SELECT id, category, key, value FROM tenant_settings
               WHERE tenant_id = $1 AND category = $2 AND key = $3"#,
        )
        .bind(tenant_id)
        .bind(category)
        .bind(key)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("TenantSetting".to_string()))?;
        Ok(row.into())
    }

    /// Upsert a single (category, key) value. Caller is expected to
    /// have already run `validate_setting_value` against `value`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn put_setting(
        &self,
        tenant_id: Uuid,
        category: &str,
        key: &str,
        value: serde_json::Value,
    ) -> AppResult<TenantSettingResponse> {
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
        .fetch_one(self.db.pool())
        .await?;
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
        tenant_id: Uuid,
        category: &str,
        key: &str,
    ) -> AppResult<()> {
        let n = sqlx::query(
            "DELETE FROM tenant_settings WHERE tenant_id = $1 AND category = $2 AND key = $3",
        )
        .bind(tenant_id)
        .bind(category)
        .bind(key)
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("TenantSetting".to_string()));
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
        tenant_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ModuleConfigResponse>, u64)> {
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM module_config WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
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
        .fetch_all(self.db.pool())
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
        tenant_id: Uuid,
        module: &str,
    ) -> AppResult<ModuleConfigResponse> {
        let row = sqlx::query_as::<_, ModCfgRow>(
            r#"SELECT id, module_name, is_enabled, config FROM module_config
               WHERE tenant_id = $1 AND module_name = $2"#,
        )
        .bind(tenant_id)
        .bind(module)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row
            .map(Into::into)
            .unwrap_or_else(|| ModuleConfigResponse::default_for(module)))
    }

    /// Read just the `is_enabled` flag, fast path used by
    /// `RequireModuleEnabled` (PMS-113 AC3). Missing row -> `false`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn is_module_enabled(&self, tenant_id: Uuid, module: &str) -> AppResult<bool> {
        let enabled: Option<bool> = sqlx::query_scalar(
            r#"SELECT COALESCE(is_enabled, FALSE) FROM module_config
               WHERE tenant_id = $1 AND module_name = $2"#,
        )
        .bind(tenant_id)
        .bind(module)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(enabled.unwrap_or(false))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_module_config(
        &self,
        tenant_id: Uuid,
        module: &str,
        request: &UpsertModuleConfigRequest,
    ) -> AppResult<ModuleConfigResponse> {
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
        .fetch_one(self.db.pool())
        .await?;
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
