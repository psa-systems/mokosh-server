//! Tenant service implementation

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::validation::slugify;

use super::models::*;

/// Tenant management service
#[derive(Clone)]
pub struct TenantService {
    db: Database,
}

impl TenantService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a new tenant
    #[tracing::instrument(skip_all)]
    pub async fn create_tenant(&self, request: &CreateTenantRequest) -> AppResult<Tenant> {
        let tenant_id = Uuid::new_v4();
        let slug = slugify(&request.slug);

        // Check if slug is unique
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)")
                .bind(&slug)
                .fetch_one(self.db.pool())
                .await?;

        if exists {
            return Err(AppError::conflict("A tenant with this slug already exists"));
        }

        // Create tenant
        let trial_ends_at = Utc::now() + Duration::days(14);

        sqlx::query(
            r#"
            INSERT INTO tenants (id, name, slug, status, billing_email, billing_contact_name,
                                 subscription_plan, subscription_status, trial_ends_at)
            VALUES ($1, $2, $3, 'active', $4, $5, $6, 'trialing', $7)
            "#,
        )
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&slug)
        .bind(&request.billing_email)
        .bind(&request.billing_contact_name)
        .bind(&request.subscription_plan)
        .bind(trial_ends_at)
        .execute(self.db.pool())
        .await?;

        // Initialize sequences
        sqlx::query("INSERT INTO ticket_sequences (tenant_id, last_number) VALUES ($1, 0)")
            .bind(tenant_id)
            .execute(self.db.pool())
            .await?;

        sqlx::query(
            "INSERT INTO invoice_sequences (tenant_id, last_number, prefix) VALUES ($1, 0, 'INV-')",
        )
        .bind(tenant_id)
        .execute(self.db.pool())
        .await?;

        // Create admin user
        let admin_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO users (id, tenant_id, email, first_name, last_name, role, status)
            VALUES ($1, $2, $3, $4, $5, 'admin', 'pending')
            "#,
        )
        .bind(admin_id)
        .bind(tenant_id)
        .bind(&request.admin_email)
        .bind(&request.admin_first_name)
        .bind(&request.admin_last_name)
        .execute(self.db.pool())
        .await?;

        // Copy default configuration from default tenant
        self.copy_default_config(tenant_id).await?;

        self.get_tenant(tenant_id).await
    }

    /// Get tenant by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_tenant(&self, tenant_id: Uuid) -> AppResult<Tenant> {
        let row = sqlx::query_as::<_, TenantRow>(
            r#"
            SELECT id, name, slug, status, settings, branding, billing_email,
                   billing_contact_name, subscription_plan, subscription_status,
                   trial_ends_at, created_at, updated_at
            FROM tenants
            WHERE id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Tenant".to_string()))?;

        Ok(row.into())
    }

    /// Get tenant by slug
    #[tracing::instrument(skip_all)]
    pub async fn get_tenant_by_slug(&self, slug: &str) -> AppResult<Tenant> {
        let row = sqlx::query_as::<_, TenantRow>(
            r#"
            SELECT id, name, slug, status, settings, branding, billing_email,
                   billing_contact_name, subscription_plan, subscription_status,
                   trial_ends_at, created_at, updated_at
            FROM tenants
            WHERE slug = $1
            "#,
        )
        .bind(slug)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Tenant".to_string()))?;

        Ok(row.into())
    }

    /// List all tenants
    #[tracing::instrument(skip_all)]
    pub async fn list_tenants(&self, page: u32, per_page: u32) -> AppResult<(Vec<Tenant>, u64)> {
        let offset = (page.saturating_sub(1)) * per_page;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(self.db.pool())
            .await?;

        let rows = sqlx::query_as::<_, TenantRow>(
            r#"
            SELECT id, name, slug, status, settings, branding, billing_email,
                   billing_contact_name, subscription_plan, subscription_status,
                   trial_ends_at, created_at, updated_at
            FROM tenants
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page as i32)
        .bind(offset as i32)
        .fetch_all(self.db.pool())
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Update tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_tenant(
        &self,
        tenant_id: Uuid,
        request: &UpdateTenantRequest,
    ) -> AppResult<Tenant> {
        let mut query = String::from("UPDATE tenants SET updated_at = NOW()");
        let mut param_idx = 2;

        if request.name.is_some() {
            query.push_str(&format!(", name = ${}", param_idx));
            param_idx += 1;
        }
        if request.billing_email.is_some() {
            query.push_str(&format!(", billing_email = ${}", param_idx));
            param_idx += 1;
        }
        if request.billing_contact_name.is_some() {
            query.push_str(&format!(", billing_contact_name = ${}", param_idx));
            param_idx += 1;
        }
        if request.settings.is_some() {
            query.push_str(&format!(", settings = ${}", param_idx));
            param_idx += 1;
        }
        if request.branding.is_some() {
            query.push_str(&format!(", branding = ${}", param_idx));
            // param_idx += 1;
        }

        query.push_str(" WHERE id = $1");

        let mut query_builder = sqlx::query(&query).bind(tenant_id);

        if let Some(ref name) = request.name {
            query_builder = query_builder.bind(name);
        }
        if let Some(ref email) = request.billing_email {
            query_builder = query_builder.bind(email);
        }
        if let Some(ref name) = request.billing_contact_name {
            query_builder = query_builder.bind(name);
        }
        if let Some(ref settings) = request.settings {
            query_builder = query_builder.bind(settings);
        }
        if let Some(ref branding) = request.branding {
            query_builder = query_builder.bind(serde_json::to_value(branding)?);
        }

        query_builder.execute(self.db.pool()).await?;

        self.get_tenant(tenant_id).await
    }

    /// Suspend tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn suspend_tenant(&self, tenant_id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE tenants SET status = 'suspended', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Activate tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn activate_tenant(&self, tenant_id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Get tenant usage statistics
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_tenant_usage(&self, tenant_id: Uuid) -> AppResult<TenantUsage> {
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(self.db.pool())
            .await?;

        let company_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM companies WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;

        let contact_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;

        let ticket_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;

        let asset_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM assets WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;

        let storage_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(file_size), 0) FROM files WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;

        Ok(TenantUsage {
            tenant_id,
            user_count,
            company_count,
            contact_count,
            ticket_count,
            asset_count,
            storage_bytes,
        })
    }

    /// Get module configuration for a tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_module_config(
        &self,
        tenant_id: Uuid,
        module_name: &str,
    ) -> AppResult<ModuleConfig> {
        let row = sqlx::query_as::<_, (String, bool, serde_json::Value)>(
            r#"
            SELECT module_name, is_enabled, config
            FROM module_config
            WHERE tenant_id = $1 AND module_name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(module_name)
        .fetch_optional(self.db.pool())
        .await?;

        match row {
            Some((name, enabled, config)) => Ok(ModuleConfig {
                module_name: name,
                is_enabled: enabled,
                config,
            }),
            None => Ok(ModuleConfig {
                module_name: module_name.to_string(),
                is_enabled: false,
                config: serde_json::json!({}),
            }),
        }
    }

    /// Update module configuration
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_module_config(
        &self,
        tenant_id: Uuid,
        module_name: &str,
        is_enabled: bool,
        config: serde_json::Value,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO module_config (tenant_id, module_name, is_enabled, config)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, module_name)
            DO UPDATE SET is_enabled = $3, config = $4, updated_at = NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(module_name)
        .bind(is_enabled)
        .bind(&config)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Copy default configuration from default tenant
    async fn copy_default_config(&self, new_tenant_id: Uuid) -> AppResult<()> {
        let default_tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        // Copy ticket statuses
        sqlx::query(
            r#"
            INSERT INTO ticket_statuses (tenant_id, name, color, is_closed, is_default, sort_order)
            SELECT $1, name, color, is_closed, is_default, sort_order
            FROM ticket_statuses WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        // Copy ticket priorities
        sqlx::query(
            r#"
            INSERT INTO ticket_priorities (tenant_id, name, color, icon, sla_multiplier, sort_order, is_default)
            SELECT $1, name, color, icon, sla_multiplier, sort_order, is_default
            FROM ticket_priorities WHERE tenant_id = $2
            "#
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        // Copy ticket types
        sqlx::query(
            r#"
            INSERT INTO ticket_types (tenant_id, name, description, icon, sort_order)
            SELECT $1, name, description, icon, sort_order
            FROM ticket_types WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        // Copy work types
        sqlx::query(
            r#"
            INSERT INTO work_types (tenant_id, name, description, default_billable, default_rate, sort_order)
            SELECT $1, name, description, default_billable, default_rate, sort_order
            FROM work_types WHERE tenant_id = $2
            "#
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        // Copy task statuses
        sqlx::query(
            r#"
            INSERT INTO task_statuses (tenant_id, name, color, is_completed, sort_order)
            SELECT $1, name, color, is_completed, sort_order
            FROM task_statuses WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        // Copy asset types
        sqlx::query(
            r#"
            INSERT INTO asset_types (tenant_id, name, icon, custom_fields_schema)
            SELECT $1, name, icon, custom_fields_schema
            FROM asset_types WHERE tenant_id = $2 AND parent_type_id IS NULL
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        // Copy module config
        sqlx::query(
            r#"
            INSERT INTO module_config (tenant_id, module_name, is_enabled, config)
            SELECT $1, module_name, is_enabled, config
            FROM module_config WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }
}

// Database row type
#[derive(sqlx::FromRow)]
struct TenantRow {
    id: Uuid,
    name: String,
    slug: String,
    status: String,
    settings: serde_json::Value,
    branding: serde_json::Value,
    billing_email: Option<String>,
    billing_contact_name: Option<String>,
    subscription_plan: Option<String>,
    subscription_status: Option<String>,
    trial_ends_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<TenantRow> for Tenant {
    fn from(row: TenantRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            slug: row.slug,
            status: TenantStatus::from_str(&row.status).unwrap_or_default(),
            settings: row.settings,
            branding: serde_json::from_value(row.branding).unwrap_or_default(),
            billing_email: row.billing_email,
            billing_contact_name: row.billing_contact_name,
            subscription_plan: row.subscription_plan,
            subscription_status: row.subscription_status,
            trial_ends_at: row.trial_ends_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
