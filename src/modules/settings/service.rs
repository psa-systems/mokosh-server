//! Settings service.

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

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
    pub async fn list_tenant_settings(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<TenantSettingResponse>> {
        let rows = sqlx::query_as::<_, SettingRow>(
            r#"SELECT id, category, key, value FROM tenant_settings
               WHERE tenant_id = $1 ORDER BY category, key"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

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

    // PMS-116 module config (parallel call path; tenants service has its
    // own implementation reachable at /api/v1/tenants/:tenant_id/modules/:module
    // -- this one lives under /api/v1/settings so the client can find it
    // without knowing the tenant id) ----------------------------------------
    pub async fn list_module_configs(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<ModuleConfigResponse>> {
        let rows = sqlx::query_as::<_, ModCfgRow>(
            r#"SELECT id, module_name, is_enabled, config FROM module_config
               WHERE tenant_id = $1 ORDER BY module_name"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

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
        .await?
        .ok_or_else(|| AppError::NotFound("ModuleConfig".to_string()))?;
        Ok(row.into())
    }

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
            id,
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
            id: r.id,
            module_name: r.module_name,
            is_enabled: r.is_enabled.unwrap_or(false),
            config: r.config,
        }
    }
}
