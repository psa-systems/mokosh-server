//! Tenant service implementation

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
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
    pub async fn create_tenant(
        &self,
        request: &CreateTenantRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Tenant> {
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

        // Mutation + audit row in one transaction: insert the tenant and its
        // seed rows, snapshot the new tenant with Postgres to_jsonb, and write
        // the audit entry on the same tx so a rollback drops both. PMS-117 AC1.
        // The tenant is its own audit scope, so tenant_id == entity_id here.
        let mut tx = self.db.pool().begin().await?;

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
        .execute(&mut *tx)
        .await?;

        // Initialize sequences
        sqlx::query("INSERT INTO ticket_sequences (tenant_id, last_number) VALUES ($1, 0)")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO invoice_sequences (tenant_id, last_number, prefix) VALUES ($1, 0, 'INV-')",
        )
        .bind(tenant_id)
        .execute(&mut *tx)
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
        .execute(&mut *tx)
        .await?;

        // The `tenants` table is keyed by `id` alone (it has no `tenant_id`
        // column), so the snapshot filters on `id`.
        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "tenants",
            Some(tenant_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

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
    pub async fn list_tenants(
        &self,
        pagination: &crate::utils::pagination::PaginationParams,
    ) -> AppResult<(Vec<Tenant>, u64)> {
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
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
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
        ctx: &AuditCtx,
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

        // Mutation + audit row in one transaction: snapshot the row before and
        // after (Postgres to_jsonb captures exact stored state) and write the
        // audit entry on the same tx so a rollback drops both. PMS-117 AC1. The
        // tenant is its own audit scope (tenant_id == entity_id) and the
        // `tenants` table is keyed by `id` alone (no `tenant_id` column).
        let mut tx = self.db.pool().begin().await?;
        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;

        query_builder.execute(&mut *tx).await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "tenants",
            Some(tenant_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

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

    // PMS-113 AC2: TenantService::get_module_config and
    // TenantService::update_module_config used to live here and ran
    // their own SQL against `module_config`, parallel to the
    // SettingsService implementation. The tenants-API handlers now
    // delegate to SettingsService (see modules/tenants/routes.rs)
    // so there is one canonical writer for `module_config`. The
    // duplicate methods were removed.

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

        // Copy the in-app notification templates + rules the background
        // workers need so a freshly created tenant fires SLA at-risk/breach
        // alerts (PMS-106) and appointment reminders (PMS-58) out of the
        // box, matching the default tenant's migration 027 / 028 seed.
        // Other transactional templates (auth.*, ticket.*) stay on the
        // migration seed / per-tenant CRUD.
        sqlx::query(
            r#"
            INSERT INTO notification_templates
                (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
            SELECT $1, name, event_type, channel_type, subject, body_text, body_html, is_active
            FROM notification_templates
            WHERE tenant_id = $2
              AND event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached')
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(self.db.pool())
        .await?;

        // Copy each default-tenant rule, re-linking template_id to the new
        // tenant's just-copied template by (event_type, channel_type) since
        // the copied template has a fresh id. Recipients ride the dispatch
        // context (the workers pass the assignee via recipient_user_id).
        sqlx::query(
            r#"
            INSERT INTO notification_rules
                (tenant_id, name, event_type, channels, recipients, template_id, is_active)
            SELECT $1, r.name, r.event_type, r.channels, r.recipients, nt.id, r.is_active
            FROM notification_rules r
            JOIN notification_templates ot
              ON ot.id = r.template_id AND ot.tenant_id = $2
            JOIN notification_templates nt
              ON nt.tenant_id = $1
             AND nt.event_type = ot.event_type
             AND nt.channel_type = ot.channel_type
            WHERE r.tenant_id = $2
              AND r.event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached')
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
