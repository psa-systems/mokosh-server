//! Tenant service implementation

use crate::modules::auth::TenantId;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::notifications::NotificationsService;
use crate::utils::crypto::{generate_token, hash_password};
use crate::utils::error::{AppError, AppResult};
use crate::utils::validation::slugify;

use super::models::*;

/// Resolve the tenant whose migration-`023` seed rows are copied into every
/// freshly provisioned tenant (see `copy_default_config`).
///
/// PMS-196: this used to be a hardcoded magic UUID parsed with `unwrap()`,
/// which panics the tenant-provisioning path on any malformed value. The
/// source is now read from `MOKOSH_SEED_TENANT_ID` (so a deployment can point
/// the seed at a different template tenant) and parsed fallibly. When the env
/// var is unset it falls back to the seed tenant created by migration 023,
/// `Uuid::from_u128(1)` (== `00000000-0000-0000-0000-000000000001`), the same
/// constant `auth::bootstrap` uses. A malformed env value is a configuration
/// error, not a panic.
fn seed_source_tenant_id() -> AppResult<Uuid> {
    match std::env::var("MOKOSH_SEED_TENANT_ID") {
        Ok(raw) => Uuid::parse_str(raw.trim()).map_err(|e| {
            AppError::Configuration(format!("MOKOSH_SEED_TENANT_ID is not a valid UUID: {e}"))
        }),
        Err(_) => Ok(Uuid::from_u128(1)),
    }
}

/// Name a personal tenant gets when nothing about its owner is usable.
///
/// PMS-743: this used to be the name EVERY personal tenant got. It is
/// customer-facing (it renders in the client request-form email subject and in
/// invitation mail), so eight staging tenants meant eight MSPs whose clients
/// received mail from "My workspace". Now it is the last resort.
const DEFAULT_PERSONAL_TENANT_NAME: &str = "My workspace";

/// `tenants.name` is `VARCHAR(255)` (migration 002), and `UpdateTenantRequest`
/// validates the same bound, so a derived name is truncated to fit rather than
/// failing the insert that provisions someone's first login.
const MAX_TENANT_NAME_LEN: usize = 255;

/// Display name for a freshly provisioned personal tenant (PMS-743).
///
/// Order of preference, and why:
///
/// 1. the IdP's `given_name`, which is a real name the owner chose;
/// 2. the first name synthesised from a real email address, reusing
///    [`synthetic_name_from_email`] so a UUID local-part or mokosh's own
///    `@unresolved.invalid` placeholder is rejected by logic that is already
///    tested, rather than by a second copy of it here;
/// 3. [`DEFAULT_PERSONAL_TENANT_NAME`].
///
/// Falling back is deliberate rather than clever: a tenant named "Mokosh
/// User's workspace" or "7fa2b249's workspace" reads worse to a client than
/// the honest generic, and the owner can rename it in Settings either way.
///
/// The possessive is always `'s`, including after a trailing s ("Chris's
/// workspace"), which is the common style and avoids branching on spelling.
fn personal_tenant_name(given_name: Option<&str>, email: Option<&str>) -> String {
    let from_given = given_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let from_email = || {
        let first = crate::modules::auth::synthetic_name_from_email(email?).0;
        // The helper returns its own fallback when it could not derive
        // anything; that is a signal, not a name.
        (first != crate::modules::auth::SYNTHETIC_NAME_FALLBACK.0 && !first.is_empty())
            .then_some(first)
    };

    match from_given.or_else(from_email) {
        Some(owner) => {
            let mut name = format!("{owner}'s workspace");
            if name.chars().count() > MAX_TENANT_NAME_LEN {
                name = name.chars().take(MAX_TENANT_NAME_LEN).collect();
            }
            name
        }
        None => DEFAULT_PERSONAL_TENANT_NAME.to_string(),
    }
}

/// Tenant management service
#[derive(Clone)]
pub struct TenantService {
    db: Database,
    // PMS-729 finalize: when the notifications dispatcher and the SPA base
    // URL are wired in, `create_tenant` mints a `password_reset_tokens` row
    // for the freshly created admin user and dispatches `auth.welcome` so
    // the admin gets an emailed setup link (same pattern
    // `AuthService::create_user(send_welcome_email = true)` already uses).
    // The default `new()` constructor leaves both `None` so the test
    // fixtures and the bunyip placement path stay untouched; only the
    // production wire path opts in via `with_dispatcher`.
    notifications: Option<NotificationsService>,
    frontend_base_url: Option<String>,
}

impl TenantService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            notifications: None,
            frontend_base_url: None,
        }
    }

    /// Attach the notifications dispatcher + SPA origin so `create_tenant`
    /// emails a `/reset-password/{token}` setup link to the fresh admin
    /// user, matching the `AuthService::create_user` welcome path.
    ///
    /// Not required for the seed / placement paths that also construct
    /// this service; the admin welcome email is a super-admin
    /// tenant-provisioning affordance.
    #[must_use]
    pub fn with_dispatcher(
        mut self,
        notifications: NotificationsService,
        frontend_base_url: String,
    ) -> Self {
        self.notifications = Some(notifications);
        self.frontend_base_url = Some(frontend_base_url.trim_end_matches('/').to_string());
        self
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

        // SAFETY (PMS-285): create_tenant is a super-admin, cross-tenant handler.
        // This uniqueness probe scans `tenants` (the RLS-exempt isolation root)
        // across every tenant, so it runs on the privileged migrator pool.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)")
                .bind(&slug)
                .fetch_one(self.db.migrator_pool())
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

        // MAPPS-396: fold caller-supplied branding into the initial
        // insert so the tenant lands with its logo / colors already set,
        // rather than a create-then-update pair. `None` maps to the
        // empty-object default so `branding` never lands NULL (the
        // column is NOT NULL DEFAULT '{}').
        let branding_json = match &request.branding {
            Some(b) => serde_json::to_value(b).unwrap_or_else(|_| serde_json::json!({})),
            None => serde_json::json!({}),
        };
        sqlx::query(
            // `kind = 'org'` is set explicitly: migration 019_tenant_kind dropped
            // the column default, so every caller must supply it. This is the
            // admin/multi-user org-create path (self-signup uses kind='personal');
            // omitting it inserts NULL and violates the NOT NULL constraint (PMS-287).
            r#"
            INSERT INTO tenants (id, name, slug, status, kind, billing_email, billing_contact_name,
                                 subscription_plan, subscription_status, trial_ends_at, branding)
            VALUES ($1, $2, $3, 'active', 'org', $4, $5, $6, 'trialing', $7, $8)
            "#,
        )
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&slug)
        .bind(&request.billing_email)
        .bind(&request.billing_contact_name)
        .bind(&request.subscription_plan)
        .bind(trial_ends_at)
        .bind(&branding_json)
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

        // PMS-413: every tenant gets an internal "own company" so general /
        // overhead time entries have a stable company_id. Idempotent.
        self.ensure_own_company(tenant_id).await?;

        // PMS-729 finalize: send the admin an emailed setup link so they can
        // choose a password and sign in. Best-effort: a failed dispatch is
        // logged but not fatal, matching `AuthService::create_user`'s welcome
        // path. Runs only when both the notifications dispatcher and the SPA
        // origin were wired via `with_dispatcher`; the seed / placement paths
        // that construct a bare service skip it and stay on their
        // pre-existing behaviour.
        self.send_admin_welcome(tenant_id, admin_id, request).await;

        // SAFETY (PMS-261): re-reading the tenant just minted above; `tenant_id`
        // is the same minted id, bridged via `from_trusted`.
        self.get_tenant(TenantId::from_trusted(tenant_id)).await
    }

    /// Emit an `auth.welcome` message with a `/reset-password/{token}` link
    /// for the freshly created tenant's admin.
    ///
    /// Reuses the `password_reset_tokens` table + token shape
    /// (`{user_id}.{secret}`) so the existing `reset_password` handler can
    /// redeem it without a parallel setup-token pipeline. The token gets a
    /// 7-day window, matching `create_user`.
    ///
    /// Best-effort: absence of a dispatcher, a dispatch failure, and even
    /// a token-insert failure all log-and-return. The tenant + admin user
    /// are already committed; refusing to return them because their mail
    /// did not send would strand the super-admin with a half-created
    /// tenant that already exists in the DB. The admin can still trigger
    /// a password-reset from the login page as a fallback.
    async fn send_admin_welcome(
        &self,
        tenant_id: Uuid,
        admin_id: Uuid,
        request: &CreateTenantRequest,
    ) {
        let (Some(notify), Some(base_url)) =
            (self.notifications.as_ref(), self.frontend_base_url.as_ref())
        else {
            return;
        };

        let secret = generate_token(64);
        let token_hash = match hash_password(&secret) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    admin_id = %admin_id,
                    error = ?e,
                    "hash_password failed while minting admin welcome token",
                );
                return;
            }
        };
        let token = format!("{}.{}", admin_id, secret);
        let expires_at = Utc::now() + Duration::days(7);

        let mut tx = match self.db.begin_with_tenant(tenant_id).await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    admin_id = %admin_id,
                    error = ?e,
                    "begin_with_tenant failed while minting admin welcome token",
                );
                return;
            }
        };
        let insert = sqlx::query(
            r#"
            INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(tenant_id)
        .bind(admin_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await;
        if let Err(e) = insert {
            tracing::warn!(
                tenant_id = %tenant_id,
                admin_id = %admin_id,
                error = ?e,
                "failed to insert admin welcome password_reset_tokens row",
            );
            return;
        }
        if let Err(e) = tx.commit().await {
            tracing::warn!(
                tenant_id = %tenant_id,
                admin_id = %admin_id,
                error = ?e,
                "commit failed on admin welcome password_reset_tokens tx",
            );
            return;
        }

        let setup_link = format!("{}/reset-password/{}", base_url, token);
        let display_name = match (
            request.admin_first_name.trim(),
            request.admin_last_name.trim(),
        ) {
            ("", "") => String::new(),
            (f, "") => f.to_string(),
            ("", l) => l.to_string(),
            (f, l) => format!("{f} {l}"),
        };
        let context = serde_json::json!({
            "recipient_user_id": admin_id.to_string(),
            "recipient_email": request.admin_email,
            "display_name": display_name,
            "setup_link": setup_link,
        });
        // SAFETY (PMS-261): `tenant_id` is freshly minted for the tenant just
        // created; `from_trusted` bridges it into the typed scope, and
        // `dispatch` sets the GUC per query via `begin_with_tenant`.
        match notify
            .dispatch(TenantId::from_trusted(tenant_id), "auth.welcome", &context)
            .await
        {
            Ok(_) => {
                tracing::info!(
                    tenant_id = %tenant_id,
                    admin_id = %admin_id,
                    "admin welcome email queued via notifications dispatcher",
                );
            }
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    admin_id = %admin_id,
                    error = ?e,
                    "welcome dispatch failed; setup token persisted but no message queued",
                );
            }
        }
    }

    /// Idempotently seed the PSA per-tenant lookup/config set (ticket statuses,
    /// priorities, queues, types, categories, work types, task statuses, asset
    /// types, rounding rules, business hours, ...) into `tenant_id`, copying it
    /// from the default tenant. A no-op when the tenant is already seeded (the
    /// presence guard in `copy_default_config`).
    ///
    /// PMS-288: `create_tenant` and `ensure_personal_tenant` seed at creation,
    /// but a user can be placed into a tenant provisioned off the PSA path (an
    /// invite into an auth/SSO-created org tenant, or a manually-created tenant)
    /// that never received this set, so ticket creation - which requires a
    /// default `ticket_statuses` row AND a `ticket_sequences` row
    /// (`tickets/service.rs`) - 500s. The placement path calls this so any
    /// tenant a user actually lands in is seeded.
    pub async fn ensure_default_config(&self, tenant_id: Uuid) -> AppResult<()> {
        // This runs on the per-request bunyip auth path (place_bunyip_user), so
        // the already-seeded common case must stay cheap: a couple of
        // `SELECT EXISTS` and no write transaction. The sequence step is guarded
        // here; the lookup step is guarded inside `copy_default_config`.
        //
        // Per-tenant sequences power ticket_number / invoice_number generation.
        // They are not part of `copy_default_config` (create_tenant seeds them
        // separately), so seed them here too - under the tenant GUC, since the
        // sequence tables are RLS-protected (mirrors create_tenant). The inserts
        // keep `ON CONFLICT DO NOTHING` so a concurrent first-request race stays
        // idempotent even though the cheap guard let both callers through.
        let has_sequences: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ticket_sequences WHERE tenant_id = $1)",
        )
        .bind(tenant_id)
        // PMS-692: `ticket_sequences` is RLS-covered, so this probe must run
        // under the tenant GUC too - on the app pool it was a permanent false
        // negative (always "no sequences"), harmless only because the inserts
        // below are idempotent.
        .fetch_one(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        if !has_sequences {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query(
                "INSERT INTO ticket_sequences (tenant_id, last_number) VALUES ($1, 0)
                 ON CONFLICT (tenant_id) DO NOTHING",
            )
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO invoice_sequences (tenant_id, last_number, prefix) VALUES ($1, 0, 'INV-')
                 ON CONFLICT (tenant_id) DO NOTHING",
            )
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        // Lookup/config set (ticket statuses/priorities/queues/types/...).
        // Idempotent: copy_default_config early-returns when already seeded.
        self.copy_default_config(tenant_id).await?;

        // PMS-413: a tenant a user lands in off the bunyip placement path (an
        // org tenant created via auth/SSO, or a manually-created tenant) may
        // never have run create_tenant, so ensure its own-company here too.
        // Idempotent: a no-op once own_company_id is set.
        self.ensure_own_company(tenant_id).await
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
    ///
    /// PMS-743: `given_name` and `email` are the IdP's, passed straight through
    /// from the placement path, and name the tenant. They are optional because
    /// neither claim is guaranteed; see [`personal_tenant_name`] for what each
    /// absence costs.
    #[tracing::instrument(skip_all, fields(owner_id = %owner_id))]
    pub async fn ensure_personal_tenant(
        &self,
        owner_id: Uuid,
        given_name: Option<&str>,
        email: Option<&str>,
    ) -> AppResult<Uuid> {
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
        .bind(personal_tenant_name(given_name, email))
        .bind(&slug)
        .bind(owner_id)
        // SAFETY (PMS-285): personal-tenant provisioning runs on the pre-session
        // bunyip placement path before the owner has any tenant context. It
        // writes the RLS-exempt `tenants` root row, so it uses the migrator pool;
        // the new tenant's own RLS-covered sequence rows are seeded under its GUC
        // in the `begin_with_tenant` block below.
        .fetch_optional(self.db.migrator_pool())
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
                // PMS-413: give the personal tenant its internal own-company so
                // general / overhead time logging works out of the box.
                self.ensure_own_company(id).await?;
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
        // SAFETY (PMS-285): resolves a personal tenant by its `personal_owner_id`
        // on the pre-session provisioning path, a cross-tenant lookup of the
        // RLS-exempt `tenants` root with no owner GUC available. Migrator pool.
        Ok(
            sqlx::query_scalar("SELECT id FROM tenants WHERE personal_owner_id = $1")
                .bind(owner_id)
                .fetch_optional(self.db.migrator_pool())
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
        // SAFETY (PMS-285 / PMS-692): the `tenants` table is the RLS-exempt
        // isolation root (migration 038 skips it), so this single-row read is
        // safe on the app pool with no GUC; the route handler enforces that a
        // non-super-admin caller may only read its own tenant id (the
        // `cross_user_tenant_endpoint_denied` regression pins it).
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
        // SAFETY (PMS-285): list_tenants is a super-admin, cross-tenant handler
        // (the route gates it on super_admin) that enumerates every tenant in the
        // RLS-exempt `tenants` root. It runs on the privileged migrator pool.
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(self.db.migrator_pool())
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
        .fetch_all(self.db.migrator_pool())
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Update tenant
    #[allow(unused_assignments)]
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
        // PMS-758: an object or nothing. A string or an array here would
        // replace the document with something no reader can destructure, and
        // `||` on two non-objects concatenates rather than merges.
        if let Some(branding) = request.branding.as_ref() {
            if !branding.is_object() {
                return Err(AppError::validation_field(
                    "branding",
                    "must be an object of branding keys",
                ));
            }
        }
        if request.branding.is_some() {
            // PMS-758: MERGE, not replace. `branding` is a JSONB document and
            // callers send the subset they own: the organisation settings page
            // writes four contact keys, the logo upload writes two others. A
            // whole-document write meant the settings page silently deleted
            // `logo_mime`, leaving `logo_url` pointing at a route that then
            // answered 404, which is a broken image in every client email.
            //
            // `||` is a top-level key merge with the right side winning, so a
            // caller still clears a key by sending it as an explicit null. That
            // is why the SPA sends nulls rather than omitting empty fields.
            query.push_str(&format!(", branding = branding || ${}::jsonb", param_idx));
            // Invariant: every conditional SET advances `param_idx` so the
            // next field added below is numbered correctly. `branding` is
            // the last field today, so this increment is currently unread
            // (`#[allow(unused_assignments)]` on the fn); keep it so the
            // pattern stays copy-paste safe (PMS-197).
            param_idx += 1;
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
        // SAFETY (PMS-285): super-admin tenant-lifecycle handler writing the
        // RLS-exempt `tenants` root row by id. Migrator pool.
        sqlx::query("UPDATE tenants SET status = 'suspended', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(self.db.migrator_pool())
            .await?;

        Ok(())
    }

    /// Activate tenant
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn activate_tenant(&self, tenant_id: TenantId) -> AppResult<()> {
        // SAFETY (PMS-285): super-admin tenant-lifecycle handler writing the
        // RLS-exempt `tenants` root row by id. Migrator pool.
        sqlx::query("UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(self.db.migrator_pool())
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

    /// Idempotently ensure `tenant_id` has an `internal` "own company" and that
    /// `tenants.own_company_id` points at it (PMS-413).
    ///
    /// A general / overhead time entry has no customer to bill, so the SPA needs
    /// a stable company id to send; this is it. Created once per tenant, named
    /// after the tenant. Mirrors the backfill in migration `062`: it only
    /// creates + links when `own_company_id` is still NULL, so a re-run (or a
    /// tenant already backfilled by the migration) is a no-op.
    ///
    /// SAFETY (PMS-285): runs on the provisioning paths (`create_tenant`,
    /// `ensure_personal_tenant`, `ensure_default_config`). The `tenants` row is
    /// the RLS-exempt isolation root and the `companies` insert is RLS-covered,
    /// so the whole unit runs under the new tenant's GUC tx (`begin_with_tenant`)
    /// so the companies WITH CHECK policy passes; the `tenants` update is exempt
    /// regardless. The guard + single tx keep concurrent provisioning races
    /// converging on one own-company.
    pub async fn ensure_own_company(&self, tenant_id: Uuid) -> AppResult<()> {
        // Cheap guard so the already-provisioned common case skips the write tx.
        // SAFETY (PMS-285 / PMS-692): `tenants` is the RLS-exempt isolation root
        // (migration 038), so this probe reads safely on the app pool with no GUC.
        let already_linked: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1 AND own_company_id IS NOT NULL)",
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await?;
        if already_linked {
            return Ok(());
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Re-read the tenant name + own_company_id under the tx so a concurrent
        // provisioner that won the race is observed (the WHERE guard below then
        // updates nothing). The tenant always exists on these paths.
        let row: Option<(String, Option<Uuid>)> =
            sqlx::query_as("SELECT name, own_company_id FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        let (tenant_name, existing) = match row {
            Some(r) => r,
            None => return Ok(()),
        };
        if existing.is_some() {
            return Ok(());
        }

        let company_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO companies (id, tenant_id, name, company_type, status) \
             VALUES ($1, $2, $3, 'internal', 'active')",
        )
        .bind(company_id)
        .bind(tenant_id)
        .bind(&tenant_name)
        .execute(&mut *tx)
        .await?;

        // Link only while still NULL so a concurrent winner is not clobbered.
        sqlx::query(
            "UPDATE tenants SET own_company_id = $2, updated_at = NOW() \
             WHERE id = $1 AND own_company_id IS NULL",
        )
        .bind(tenant_id)
        .bind(company_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Seed a freshly provisioned tenant with the full default set of
    /// user-editable lookup / configuration rows, scoped to that tenant.
    ///
    /// PMS-259: under the personal-tenant-per-user isolation model
    /// (`docs/rls-per-user-isolation.md`) lookup tables are editable, so
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
        let default_tenant = seed_source_tenant_id()?;

        // SAFETY (PMS-285): this seed is intrinsically cross-tenant - it READS
        // the default tenant's lookup rows and WRITES copies re-scoped to
        // `new_tenant_id`. No single `app.current_tenant` GUC can satisfy both
        // sides (a GUC of `new_tenant_id` would RLS-hide the default-tenant
        // source rows; a GUC of the default tenant would reject the WITH CHECK on
        // the new-tenant inserts). It is provisioning, run before the owner has a
        // session, so it uses the privileged migrator (BYPASSRLS) pool.
        let mut tx = self.db.migrator_pool().begin().await?;

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

        // Project types (PMS-322), including the is_system flag so the seeded
        // client/internal rows stay delete-protected in the new tenant.
        sqlx::query(
            r#"
            INSERT INTO project_types (tenant_id, name, is_default, is_active, sort_order, is_system)
            SELECT $1, name, is_default, is_active, sort_order, is_system
            FROM project_types WHERE tenant_id = $2
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

        // Company industries (PMS-601): the suggestion vocabulary for the
        // company Industry combobox.
        sqlx::query(
            r#"
            INSERT INTO company_industries (tenant_id, name, is_active)
            SELECT $1, name, is_active
            FROM company_industries WHERE tenant_id = $2
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

        // Payment terms (PMS-333)
        sqlx::query(
            r#"
            INSERT INTO payment_terms (tenant_id, name, is_default, is_active, sort_order)
            SELECT $1, name, is_default, is_active, sort_order
            FROM payment_terms WHERE tenant_id = $2
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
        // PMS-700 adds the auth.* transactional templates: the dispatcher is
        // now their only delivery path (the duplicate hard-coded bodies in
        // `Mailer` are gone), so a tenant without these rows would get no
        // password-reset or welcome mail at all. Migration 097 backfills the
        // same two event types into tenants created before this. Other
        // transactional templates (ticket.*) stay on the migration seed /
        // per-tenant CRUD.
        sqlx::query(
            r#"
            INSERT INTO notification_templates
                (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
            SELECT $1, name, event_type, channel_type, subject, body_text, body_html, is_active
            FROM notification_templates
            WHERE tenant_id = $2
              AND event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached',
                                 'auth.password_reset', 'auth.welcome',
                                 -- PMS-730: without this a tenant created from
                                 -- here on would silently send no request-form
                                 -- link email at all, since the dispatcher is
                                 -- the only delivery path (migration 097).
                                 'forms.request_link',
                                 -- PMS-761: seeded for the default tenant by
                                 -- migration 021 and never copied, so the
                                 -- public ticket-note email has been fanning
                                 -- out to zero recipients for every real
                                 -- tenant while the note row was still marked
                                 -- sent. Migration 104 backfills the tenants
                                 -- created before this line existed.
                                 'ticket.note_added')
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
              AND r.event_type IN ('appointment.reminder', 'sla.at_risk', 'sla.breached',
                                   'auth.password_reset', 'auth.welcome',
                                   -- PMS-761: the two client-facing events.
                                   -- Their templates were copied above and
                                   -- their rules were not, and `dispatch`
                                   -- iterates RULES: a template with no rule
                                   -- is a message that is never sent.
                                   'forms.request_link', 'ticket.note_added')
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_given_name_wins() {
        assert_eq!(
            personal_tenant_name(Some("Long"), Some("long@example.com")),
            "Long's workspace"
        );
    }

    #[test]
    fn a_missing_given_name_falls_back_to_the_email() {
        assert_eq!(
            personal_tenant_name(None, Some("dana.reid@example.com")),
            "Dana's workspace"
        );
    }

    #[test]
    fn a_blank_given_name_is_treated_as_absent() {
        // The IdP can return an empty string rather than omitting the claim;
        // "'s workspace" would be worse than the generic.
        assert_eq!(
            personal_tenant_name(Some("   "), Some("dana@example.com")),
            "Dana's workspace"
        );
    }

    #[test]
    fn an_unusable_owner_keeps_the_generic_name() {
        // mokosh's own JIT placeholder address, and a UUID local-part: naming a
        // tenant "Mokosh User's workspace" or "7fa2b249's workspace" in front of
        // a client is worse than saying nothing about the owner.
        let sub = "7fa2b249-6132-4abc-90de-1f2e3d4c5b6a";
        assert_eq!(
            personal_tenant_name(None, Some(&format!("{sub}@unresolved.invalid"))),
            DEFAULT_PERSONAL_TENANT_NAME
        );
        assert_eq!(
            personal_tenant_name(None, Some(&format!("{sub}@example.com"))),
            DEFAULT_PERSONAL_TENANT_NAME
        );
        assert_eq!(
            personal_tenant_name(None, None),
            DEFAULT_PERSONAL_TENANT_NAME
        );
    }

    #[test]
    fn a_long_name_is_truncated_to_the_column_width() {
        // Provisioning runs on someone's first login; a name too long for
        // VARCHAR(255) must not be the thing that fails it.
        let long = "a".repeat(400);
        let name = personal_tenant_name(Some(&long), None);
        assert_eq!(name.chars().count(), MAX_TENANT_NAME_LEN);
    }

    #[test]
    fn a_trailing_s_still_takes_an_apostrophe_s() {
        assert_eq!(
            personal_tenant_name(Some("Chris"), None),
            "Chris's workspace"
        );
    }
}
