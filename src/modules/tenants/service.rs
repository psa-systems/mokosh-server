//! Tenant service implementation

use crate::modules::auth::TenantId;
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
        // The block writes tenant-scoped tables (users, sequences, audit_log)
        // under the new tenant, so route through the tenant GUC tx so the RLS
        // WITH CHECK policies see app.current_tenant. PMS-256.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

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

        // SAFETY (PMS-261): `tenant_id` is freshly minted for the tenant being
        // created (not a caller-supplied claim) and the whole block runs inside
        // `begin_with_tenant(tenant_id)` (see the GUC note above), so the audit
        // row is written under that tenant's GUC. `from_trusted` bridges the
        // minted `Uuid` into the typed scope `audit_write` requires.
        audit_write(
            &mut *tx,
            TenantId::from_trusted(tenant_id),
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

        // SAFETY (PMS-261): re-reading the tenant just minted above; `tenant_id`
        // is the same minted id, bridged via `from_trusted`.
        self.get_tenant(TenantId::from_trusted(tenant_id)).await
    }

    /// Find-or-provision the `personal` tenant owned by `owner_id` (PMS-244).
    /// A brand-new SSO user with no invite lands here: their own one-person org.
    ///
    /// Idempotent and race-safe: the partial unique index on
    /// `tenants.personal_owner_id` makes concurrent first-logins converge on one
    /// tenant (the `ON CONFLICT` loser re-reads the winner). The tenant gets the
    /// same sequences + default config (`copy_default_config`) a normally
    /// created tenant does, so it works out of the box; the owning user is
    /// JIT-mirrored separately.
    #[tracing::instrument(skip_all, fields(owner_id = %owner_id))]
    pub async fn ensure_personal_tenant(&self, owner_id: Uuid) -> AppResult<Uuid> {
        if let Some(id) = self.personal_tenant_for_owner(owner_id).await? {
            return Ok(id);
        }

        let tenant_id = Uuid::new_v4();
        // A uuid-derived slug guarantees uniqueness without a human display name
        // (personal tenants are auto-provisioned; the owner can rename later).
        let slug = slugify(&format!(
            "personal-{}",
            &tenant_id.simple().to_string()[..12]
        ));

        let inserted: Option<Uuid> = sqlx::query_scalar(
            r#"INSERT INTO tenants (id, name, slug, kind, status, subscription_status, personal_owner_id)
               VALUES ($1, $2, $3, 'personal', 'active', 'active', $4)
               ON CONFLICT (personal_owner_id) WHERE personal_owner_id IS NOT NULL DO NOTHING
               RETURNING id"#,
        )
        .bind(tenant_id)
        .bind("My workspace")
        .bind(&slug)
        .bind(owner_id)
        .fetch_optional(self.db.pool())
        .await?;

        match inserted {
            Some(id) => {
                // Seed the new tenant's RLS-protected sequence rows under its
                // own tenant GUC so the WITH CHECK policies pass. The earlier
                // INSERT into `tenants` stays on the pool because RLS is not
                // enabled on that table. PMS-256.
                let mut tx = self.db.begin_with_tenant(id).await?;
                sqlx::query("INSERT INTO ticket_sequences (tenant_id, last_number) VALUES ($1, 0)")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(
                    "INSERT INTO invoice_sequences (tenant_id, last_number, prefix) VALUES ($1, 0, 'INV-')",
                )
                .bind(id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                self.copy_default_config(id).await?;
                tracing::info!(tenant_id = %id, owner_id = %owner_id, "provisioned personal tenant");
                Ok(id)
            }
            // Lost the insert race: another request provisioned it concurrently.
            None => self
                .personal_tenant_for_owner(owner_id)
                .await?
                .ok_or_else(|| {
                    AppError::Internal("personal tenant missing after insert conflict".to_string())
                }),
        }
    }

    /// The `personal` tenant id owned by `owner_id`, if one exists yet.
    async fn personal_tenant_for_owner(&self, owner_id: Uuid) -> AppResult<Option<Uuid>> {
        Ok(
            sqlx::query_scalar("SELECT id FROM tenants WHERE personal_owner_id = $1")
                .bind(owner_id)
                .fetch_optional(self.db.pool())
                .await?,
        )
    }

    /// Get tenant by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_tenant(&self, tenant_id: TenantId) -> AppResult<Tenant> {
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
        tenant_id: TenantId,
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
        // The audit_log write at the end of this tx IS RLS-protected, so route
        // the block through the tenant GUC tx so its WITH CHECK policy passes.
        // PMS-256.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
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
            Some(tenant_id.get()),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_tenant(tenant_id).await
    }

    /// Suspend tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn suspend_tenant(&self, tenant_id: TenantId) -> AppResult<()> {
        sqlx::query("UPDATE tenants SET status = 'suspended', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Activate tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn activate_tenant(&self, tenant_id: TenantId) -> AppResult<()> {
        sqlx::query("UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    /// Get tenant usage statistics
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_tenant_usage(&self, tenant_id: TenantId) -> AppResult<TenantUsage> {
        // All counts read RLS-protected per-tenant tables filtered by
        // tenant_id = $1, so run them on one shared tenant GUC tx so the RLS
        // USING policies see app.current_tenant. Reads need no commit. PMS-256.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;

        let company_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM companies WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let contact_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let ticket_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let asset_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM assets WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let storage_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(file_size), 0) FROM files WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;

        Ok(TenantUsage {
            tenant_id: tenant_id.get(),
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

    /// Seed a freshly provisioned tenant with the full default set of
    /// user-editable lookup / configuration rows, scoped to that tenant.
    ///
    /// PMS-259: under the personal-tenant-per-user isolation model
    /// (`dev-docs/rls-per-user-isolation.md`) lookup tables are editable, so
    /// every user owns their own copies; a fresh tenant must not start with
    /// empty status / priority / type / work-type lists. The rows are copied
    /// from the migration-`023` seed held by the default tenant
    /// (`00000000-0000-0000-0000-000000000001`) and re-scoped to
    /// `new_tenant_id`. Foreign keys between lookups (sla_policies ->
    /// business_hours, sla_targets -> sla_policies / ticket_priorities,
    /// rate_card_items -> rate_cards / work_types, child categories ->
    /// parents) are re-linked to the new tenant's freshly copied rows by name.
    ///
    /// Idempotent: if the tenant already holds lookup rows the whole seed is
    /// skipped, so a re-run (or a retried provisioning) never double-seeds.
    /// The copy runs in one transaction so a fresh tenant is either fully
    /// seeded or not at all.
    async fn copy_default_config(&self, new_tenant_id: Uuid) -> AppResult<()> {
        let default_tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        let mut tx = self.db.pool().begin().await?;

        // Idempotency guard: ticket_statuses is seeded for every tenant, so its
        // presence means this tenant was already seeded. Skip rather than
        // duplicate (AC: "skip when the tenant already has rows").
        let already_seeded: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ticket_statuses WHERE tenant_id = $1)")
                .bind(new_tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        if already_seeded {
            return Ok(());
        }

        // Business hours first: sla_policies references it.
        sqlx::query(
            r#"
            INSERT INTO business_hours (tenant_id, name, timezone, schedule, is_default)
            SELECT $1, name, timezone, schedule, is_default
            FROM business_hours WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Ticket statuses
        sqlx::query(
            r#"
            INSERT INTO ticket_statuses (tenant_id, name, color, is_closed, is_default, sort_order)
            SELECT $1, name, color, is_closed, is_default, sort_order
            FROM ticket_statuses WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Ticket priorities (sla_targets re-links to these by name)
        sqlx::query(
            r#"
            INSERT INTO ticket_priorities (tenant_id, name, color, icon, sla_multiplier, sort_order, is_default)
            SELECT $1, name, color, icon, sla_multiplier, sort_order, is_default
            FROM ticket_priorities WHERE tenant_id = $2
            "#
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Ticket types
        sqlx::query(
            r#"
            INSERT INTO ticket_types (tenant_id, name, description, icon, sort_order)
            SELECT $1, name, description, icon, sort_order
            FROM ticket_types WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Ticket categories: parents first, then children re-linked to the new
        // tenant's parents by name (parent_id references the same table).
        sqlx::query(
            r#"
            INSERT INTO ticket_categories (tenant_id, parent_id, name, description, sort_order)
            SELECT $1, NULL, name, description, sort_order
            FROM ticket_categories WHERE tenant_id = $2 AND parent_id IS NULL
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO ticket_categories (tenant_id, parent_id, name, description, sort_order)
            SELECT $1, np.id, c.name, c.description, c.sort_order
            FROM ticket_categories c
            JOIN ticket_categories dp ON dp.id = c.parent_id AND dp.tenant_id = $2
            JOIN ticket_categories np ON np.tenant_id = $1 AND np.name = dp.name AND np.parent_id IS NULL
            WHERE c.tenant_id = $2 AND c.parent_id IS NOT NULL
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Ticket queues (team / sla links are tenant-specific and stay NULL,
        // matching the migration-023 seed)
        sqlx::query(
            r#"
            INSERT INTO ticket_queues (tenant_id, name, description, color, is_default, sort_order)
            SELECT $1, name, description, color, is_default, sort_order
            FROM ticket_queues WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Work types (rate_card_items re-links to these by name)
        sqlx::query(
            r#"
            INSERT INTO work_types (tenant_id, name, description, default_billable, default_rate, sort_order)
            SELECT $1, name, description, default_billable, default_rate, sort_order
            FROM work_types WHERE tenant_id = $2
            "#
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Task statuses
        sqlx::query(
            r#"
            INSERT INTO task_statuses (tenant_id, name, color, is_completed, sort_order)
            SELECT $1, name, color, is_completed, sort_order
            FROM task_statuses WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Asset types (top-level only, matching prior behaviour)
        sqlx::query(
            r#"
            INSERT INTO asset_types (tenant_id, name, icon, custom_fields_schema)
            SELECT $1, name, icon, custom_fields_schema
            FROM asset_types WHERE tenant_id = $2 AND parent_type_id IS NULL
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Time rounding rules
        sqlx::query(
            r#"
            INSERT INTO time_rounding_rules (tenant_id, name, increment_minutes, rounding_method, minimum_minutes, is_default)
            SELECT $1, name, increment_minutes, rounding_method, minimum_minutes, is_default
            FROM time_rounding_rules WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Tax rates
        sqlx::query(
            r#"
            INSERT INTO tax_rates (tenant_id, name, rate, is_default, is_active)
            SELECT $1, name, rate, is_default, is_active
            FROM tax_rates WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // KB categories: parents first, then children re-linked by name.
        sqlx::query(
            r#"
            INSERT INTO kb_categories (tenant_id, parent_id, name, description, slug, visibility, sort_order)
            SELECT $1, NULL, name, description, slug, visibility, sort_order
            FROM kb_categories WHERE tenant_id = $2 AND parent_id IS NULL
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO kb_categories (tenant_id, parent_id, name, description, slug, visibility, sort_order)
            SELECT $1, np.id, c.name, c.description, c.slug, c.visibility, c.sort_order
            FROM kb_categories c
            JOIN kb_categories dp ON dp.id = c.parent_id AND dp.tenant_id = $2
            JOIN kb_categories np ON np.tenant_id = $1 AND np.name = dp.name AND np.parent_id IS NULL
            WHERE c.tenant_id = $2 AND c.parent_id IS NOT NULL
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Rate cards, then their items re-linked to the new tenant's rate cards
        // and work types by name.
        sqlx::query(
            r#"
            INSERT INTO rate_cards (tenant_id, name, description, is_default)
            SELECT $1, name, description, is_default
            FROM rate_cards WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO rate_card_items (rate_card_id, work_type_id, hourly_rate, after_hours_rate, emergency_rate)
            SELECT nrc.id, nwt.id, i.hourly_rate, i.after_hours_rate, i.emergency_rate
            FROM rate_card_items i
            JOIN rate_cards drc ON drc.id = i.rate_card_id AND drc.tenant_id = $2
            JOIN rate_cards nrc ON nrc.tenant_id = $1 AND nrc.name = drc.name
            JOIN work_types dwt ON dwt.id = i.work_type_id AND dwt.tenant_id = $2
            JOIN work_types nwt ON nwt.tenant_id = $1 AND nwt.name = dwt.name
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // SLA policies (business_hours re-linked by name), then targets
        // (sla_policies + ticket_priorities re-linked by name).
        sqlx::query(
            r#"
            INSERT INTO sla_policies (tenant_id, name, description, business_hours_id, is_default)
            SELECT $1, p.name, p.description, nbh.id, p.is_default
            FROM sla_policies p
            LEFT JOIN business_hours dbh ON dbh.id = p.business_hours_id AND dbh.tenant_id = $2
            LEFT JOIN business_hours nbh ON nbh.tenant_id = $1 AND nbh.name = dbh.name
            WHERE p.tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO sla_targets (sla_policy_id, priority_id, first_response_hours, resolution_hours, operational_hours)
            SELECT np.id, npr.id, t.first_response_hours, t.resolution_hours, t.operational_hours
            FROM sla_targets t
            JOIN sla_policies dp ON dp.id = t.sla_policy_id AND dp.tenant_id = $2
            JOIN sla_policies np ON np.tenant_id = $1 AND np.name = dp.name
            JOIN ticket_priorities dpr ON dpr.id = t.priority_id AND dpr.tenant_id = $2
            JOIN ticket_priorities npr ON npr.tenant_id = $1 AND npr.name = dpr.name
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
        .await?;

        // Module config
        sqlx::query(
            r#"
            INSERT INTO module_config (tenant_id, module_name, is_enabled, config)
            SELECT $1, module_name, is_enabled, config
            FROM module_config WHERE tenant_id = $2
            "#,
        )
        .bind(new_tenant_id)
        .bind(default_tenant)
        .execute(&mut *tx)
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
        .execute(&mut *tx)
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
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
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
