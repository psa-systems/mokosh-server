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

use super::branding::validate_branding_patch;
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
///
/// PMS-836: an empty value reads as unset, like every other optional var here.
/// `compose.dev.yml` enumerates the environment, so a forwarded-but-unset key
/// arrives as `""`; without this it would fail tenant provisioning outright.
fn seed_source_tenant_id() -> AppResult<Uuid> {
    parse_seed_source_tenant_id(std::env::var("MOKOSH_SEED_TENANT_ID").ok().as_deref())
}

/// The pure parse, split out so it is unit-testable without process env
/// (same shape as `seed::service::seed_enabled_for`).
fn parse_seed_source_tenant_id(raw: Option<&str>) -> AppResult<Uuid> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(value) => Uuid::parse_str(value).map_err(|e| {
            AppError::Configuration(format!("MOKOSH_SEED_TENANT_ID is not a valid UUID: {e}"))
        }),
        None => Ok(Uuid::from_u128(1)),
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

/// How long a tenant stays memoized as "already seeded" (PMS-777). The entry
/// is a pure memoization of an idempotent guard, so the only failure mode is a
/// stale positive after somebody empties a lookup table by hand; it clears
/// within the TTL and a restart re-checks everything.
const SEEDED_TENANT_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Cap on memoized tenants (PMS-777). Bounds the map on a deployment with many
/// tenants; an evicted entry just costs one more probe.
const SEEDED_TENANT_CAPACITY: u64 = 10_000;

/// Tenant management service
#[derive(Clone)]
pub struct TenantService {
    pub(crate) db: Database,
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
    /// MAPPS-457: instance-wide hard ceiling on total tenants. `None`
    /// leaves creation uncapped (production default). `Some(N)` makes
    /// [`create_tenant`] probe `SELECT COUNT(*) FROM tenants` before
    /// insert and return 409 when the current count is >= N. The value
    /// is re-read from `self` on every create call, so raising / lowering
    /// the env at boot re-boots into the new ceiling with no restart of
    /// downstream services.
    max_tenants: Option<usize>,
    /// PMS-777: tenants this process has already seen `ensure_default_config`
    /// succeed for. `ensure_default_config` runs on the per-request bunyip auth
    /// path, where its three `SELECT EXISTS` guards cost round trips forever to
    /// answer a question that flips at most once per tenant.
    seeded_tenants: moka::future::Cache<Uuid, ()>,
}

impl TenantService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            notifications: None,
            frontend_base_url: None,
            max_tenants: None,
            seeded_tenants: moka::future::Cache::builder()
                .max_capacity(SEEDED_TENANT_CAPACITY)
                .time_to_live(SEEDED_TENANT_TTL)
                .build(),
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

    /// MAPPS-457: attach an instance-wide tenant creation cap. `None`
    /// leaves creation uncapped; `Some(N)` (N > 0) makes
    /// [`create_tenant`] return `AppError::Conflict` once the tenants
    /// row count reaches N.
    #[must_use]
    pub fn with_max_tenants(mut self, cap: Option<usize>) -> Self {
        self.max_tenants = cap.filter(|n| *n > 0);
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

        // MAPPS-457: enforce instance-wide tenant creation cap when
        // `MOKOSH_MAX_TENANTS` is configured. Count is on the migrator
        // pool for the same RLS-exempt reason the uniqueness probe uses.
        // Skipped entirely when uncapped so the common case does not
        // pay for an extra COUNT(*).
        if let Some(cap) = self.max_tenants {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
                .fetch_one(self.db.migrator_pool())
                .await?;
            if (count as usize) >= cap {
                return Err(AppError::conflict(format!(
                    "Tenant creation cap reached ({cap}); contact your operator to raise MOKOSH_MAX_TENANTS."
                )));
            }
        }

        // MAPPS-457: enforce case-insensitive name uniqueness across
        // non-personal tenants. The DB-level partial unique index (see
        // migration `..._tenants_unique_name`) is the ultimate guard;
        // this probe just yields a nicer error message than the raw
        // sqlx unique-violation. Personal tenants have auto-generated
        // names ("Chris's workspace") that can genuinely collide, so
        // they are exempt from both this probe and the index.
        let name_taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tenants \
             WHERE LOWER(name) = LOWER($1) AND personal_owner_id IS NULL)",
        )
        .bind(&request.name)
        .fetch_one(self.db.migrator_pool())
        .await?;
        if name_taken {
            return Err(AppError::conflict("A tenant with this name already exists"));
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

        // MAPPS-554: no `users` row for the client ADMIN. Pre-554 the
        // provisioner inserted a `users` row (`role='admin',
        // status='pending'`) and mailed a mokosh-workspace setup link
        // pointing at `/set-password/<user-token>`. The operator's
        // 2026-08-24 walkthrough made explicit that a mokosh-client's
        // world is the customer portal (`/portal/*`), not the mokosh
        // workspace: "the owner of the client portal be an admin in
        // their own client portal which is the customer portal that
        // we made earlier." The portal-admin CONTACT + `portal_setup_tokens`
        // row are provisioned after this tx commits (once `ensure_own_company`
        // has minted the tenant's own_company for the contact FK), via
        // `provision_portal_admin_and_send_welcome` below. See MAPPS-554.
        //
        // MAPPS-562: even though NO human user gets a users row,
        // several server code paths still need SOME users row to
        // attribute writes to (tickets.created_by_id is a NOT NULL
        // FK to users; email intake + portal ticket creation +
        // portal note acceptance all fall back to
        // `SELECT id FROM users WHERE tenant_id=$1 AND status='active'
        // AND role IN ('super_admin','admin','manager') ORDER BY
        // created_at LIMIT 1`). Insert a hidden "system" row whose
        // email is a reserved suffix and whose password_hash is NULL
        // (AuthService::login 401s on NULL hash so the row is
        // unloginable). Migration 137 backfills the same shape for
        // pre-562 tenants. The MAPPS-498 mirror trigger will fan
        // this insert out to identities + memberships; both stay
        // unloginable since there is no password_hash.
        sqlx::query(
            r#"
            INSERT INTO users (tenant_id, email, first_name, last_name, role, status)
            VALUES ($1, 'system+' || $2 || '@mokosh.local',
                    'System', 'Attribution', 'admin', 'active')
            "#,
        )
        .bind(tenant_id)
        .bind(&slug)
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

        // mokosh-contact-login prompt 001: the MAPPS-554
        // `provision_portal_admin_and_send_welcome` call retired with
        // the /portal/* customer-portal surface. Client-side portal
        // access now comes from the CRM: MSP admin creates a Company +
        // Contacts in the standard Contacts tab, then explicitly
        // grants portal access via
        // `ContactService::grant_portal_access` (prompt 003).
        //
        // mokosh-contact-login prompt 002: seed the three built-in
        // portal roles (Billing Contact / Support Contact / Read-
        // Only) so a fresh tenant has something to assign in the
        // Contact edit page from day one. Mirrors migration 142's
        // shape for existing tenants; ON CONFLICT keeps this idempotent
        // against a re-run.
        self.seed_builtin_portal_roles(tenant_id).await?;

        // SAFETY (PMS-261): re-reading the tenant just minted above; `tenant_id`
        // is the same minted id, bridged via `from_trusted`.
        self.get_tenant(TenantId::from_trusted(tenant_id)).await
    }

    /// MAPPS-493 (MAPPS-474 phase 4): create a tenant on behalf of an
    /// already-authenticated identity. Unlike `create_tenant` (which is
    /// the super-admin "provision a tenant for someone else" flow), the
    /// caller here IS the admin: the admin user row lands with
    /// `status='active'` and the identity's own `password_hash`, so no
    /// welcome email + no `password_reset_token` are minted.
    ///
    /// Returns `(Tenant, admin_user_id)` so the caller can immediately
    /// mint a session for the fresh admin.
    ///
    /// Shares uniqueness, cap enforcement, sequence seeding, default
    /// config copy, and own-company provisioning with `create_tenant`
    /// by opening the same transaction shape; the divergence is in the
    /// admin-user INSERT (status + password_hash) and the absence of the
    /// welcome-email dispatch.
    #[tracing::instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub async fn create_tenant_for_identity(
        &self,
        email: &str,
        first_name: &str,
        last_name: &str,
        password_hash: Option<&str>,
        tenant_name: &str,
        tenant_slug: Option<&str>,
        ctx: &AuditCtx,
    ) -> AppResult<(Tenant, Uuid)> {
        let tenant_id = Uuid::new_v4();
        let admin_id = Uuid::new_v4();

        // Slug: caller-provided if non-empty, else slugified from name.
        // slugify() may collapse to empty on all-non-alphanumeric input;
        // reject with a validation-shaped error so the caller can retry.
        let raw_slug = tenant_slug
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(tenant_name);
        let slug = slugify(raw_slug);
        if slug.is_empty() {
            return Err(AppError::BadRequest(
                "Tenant name has no URL-safe characters; provide an explicit slug".to_string(),
            ));
        }

        // Uniqueness + cap probes on the RLS-exempt migrator pool
        // (mirrors create_tenant).
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)")
                .bind(&slug)
                .fetch_one(self.db.migrator_pool())
                .await?;
        if exists {
            return Err(AppError::conflict("A tenant with this slug already exists"));
        }
        if let Some(cap) = self.max_tenants {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
                .fetch_one(self.db.migrator_pool())
                .await?;
            if (count as usize) >= cap {
                return Err(AppError::conflict(format!(
                    "Tenant creation cap reached ({cap}); contact your operator to raise MOKOSH_MAX_TENANTS."
                )));
            }
        }
        let name_taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM tenants \
             WHERE LOWER(name) = LOWER($1) AND personal_owner_id IS NULL)",
        )
        .bind(tenant_name)
        .fetch_one(self.db.migrator_pool())
        .await?;
        if name_taken {
            return Err(AppError::conflict("A tenant with this name already exists"));
        }

        let trial_ends_at = Utc::now() + Duration::days(14);
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        sqlx::query(
            r#"
            INSERT INTO tenants (id, name, slug, status, kind, subscription_status, trial_ends_at, branding)
            VALUES ($1, $2, $3, 'active', 'org', 'trialing', $4, '{}'::jsonb)
            "#,
        )
        .bind(tenant_id)
        .bind(tenant_name)
        .bind(&slug)
        .bind(trial_ends_at)
        .execute(&mut *tx)
        .await?;

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

        // Admin user row for the identity. Phase-1 trigger creates the
        // matching `tenant_memberships` row (role='admin') and, if no
        // identity exists for this email yet, mirrors the users row into
        // `identities`. For the self-serve happy path an identity
        // already exists (the caller just authenticated with it), so
        // only the membership row lands.
        sqlx::query(
            r#"
            INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status, email_verified_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'admin', 'active', NOW())
            "#,
        )
        .bind(admin_id)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(first_name)
        .bind(last_name)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;

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

        self.copy_default_config(tenant_id).await?;
        self.ensure_own_company(tenant_id).await?;

        let tenant = self.get_tenant(TenantId::from_trusted(tenant_id)).await?;
        Ok((tenant, admin_id))
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
    // Contact-plane retirement fallout; retained pending MAPPS-656/657 restoration decision
    #[allow(dead_code)]
    async fn provision_portal_admin_and_send_welcome(
        &self,
        tenant_id: Uuid,
        request: &CreateTenantRequest,
    ) {
        // MAPPS-554: provision the portal admin CONTACT first (needs
        // the tenant's own_company for the FK), then mint the portal
        // setup token and dispatch the welcome. Two calls so a token
        // insert / dispatch failure does not roll back the contact.
        let contact_id = match self
            .insert_portal_admin_contact(
                tenant_id,
                &request.admin_email,
                &request.admin_first_name,
                &request.admin_last_name,
            )
            .await
        {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    error = ?e,
                    "MAPPS-554: portal admin contact insert failed; tenant is created \
                     but has no portal owner. Retry via TenantService::resend_admin_welcome.",
                );
                return;
            }
        };
        self.mint_and_send_portal_welcome(
            tenant_id,
            contact_id,
            &request.admin_email,
            &request.admin_first_name,
            &request.admin_last_name,
            &request.slug,
        )
        .await;
    }

    /// MAPPS-554: insert the tenant's portal-owner contact.
    ///
    /// Runs in its own `begin_with_tenant` tx so the contacts insert
    /// passes the RLS WITH CHECK policy against `app.current_tenant`.
    /// Reads the tenant's `own_company_id` under the same GUC (the
    /// caller's prior `ensure_own_company` populated it). Fails
    /// closed if `own_company_id` is still NULL: that means the
    /// caller skipped `ensure_own_company` (a programming error - the
    /// contacts.company_id FK is NOT NULL).
    // Contact-plane retirement fallout; retained pending MAPPS-656/657 restoration decision
    #[allow(dead_code)]
    async fn insert_portal_admin_contact(
        &self,
        tenant_id: Uuid,
        admin_email: &str,
        admin_first_name: &str,
        admin_last_name: &str,
    ) -> AppResult<Uuid> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let own_company_id: Option<Uuid> =
            sqlx::query_scalar("SELECT own_company_id FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        let Some(company_id) = own_company_id else {
            return Err(AppError::Internal(
                "tenant has no own_company_id; ensure_own_company must run before \
                 insert_portal_admin_contact"
                    .to_string(),
            ));
        };
        let contact_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO contacts (
                id, tenant_id, company_id, first_name, last_name, email,
                is_portal_user, portal_role, contact_type, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, TRUE, 'admin', 'primary', 'active')
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .bind(company_id)
        .bind(admin_first_name)
        .bind(admin_last_name)
        .bind(admin_email)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(contact_id)
    }

    /// MAPPS-554: mint a fresh `portal_setup_tokens` row for the tenant's
    /// portal admin contact and dispatch the `auth.welcome` email. Shared
    /// by `provision_portal_admin_and_send_welcome` (create path) and
    /// `resend_admin_welcome` (MAPPS-448 re-issue path), so both use the
    /// same token shape, 72h expiry (mirrors PMS-136), template context,
    /// and best-effort failure semantics.
    ///
    /// Best-effort: absence of a dispatcher, absence of a frontend base
    /// URL, absence of a portal host suffix, a failed token insert, and
    /// a failed dispatch each log-and-return. On-disk state (the token
    /// row) is committed before dispatch, so a mail failure leaves a
    /// redeemable link the operator can resend.
    async fn mint_and_send_portal_welcome(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        admin_email: &str,
        admin_first_name: &str,
        admin_last_name: &str,
        tenant_slug: &str,
    ) {
        // MAPPS-554: dispatch requires the notifications wire; the
        // portal setup URL requires the portal host suffix (there is
        // no legacy same-origin fallback here - the point of the
        // ticket is that the mokosh apex is NOT the destination).
        // Absence of either logs-and-returns; the token row is not
        // minted in that case, so a later resend re-issues cleanly.
        let Some(notify) = self.notifications.as_ref() else {
            tracing::warn!(
                tenant_id = %tenant_id,
                contact_id = %contact_id,
                "MAPPS-554: no notifications dispatcher wired; portal welcome not queued",
            );
            return;
        };
        // MAPPS-649: the portal now lives at a single host (typically
        // `portal.<apex>`) rather than per-MSP subdomains, so the
        // welcome URL is `{frontend_base_url}/portal/set-password?token={token}`
        // - the SPA at that origin serves the `/portal/*` route tree.
        // `with_dispatcher` sets `frontend_base_url`; without it we
        // have no origin to build a link against and log-and-return
        // the same way the pre-MAPPS-649 code did for a missing suffix.
        let Some(portal_base) = self.frontend_base_url.as_deref() else {
            tracing::warn!(
                tenant_id = %tenant_id,
                contact_id = %contact_id,
                "MAPPS-649: no frontend base URL configured; cannot build portal setup URL",
            );
            return;
        };

        let secret = generate_token(64);
        let token_hash = match hash_password(&secret) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    contact_id = %contact_id,
                    error = ?e,
                    "MAPPS-554: hash_password failed while minting portal setup token",
                );
                return;
            }
        };
        let token = format!("{}.{}", contact_id, secret);
        // 72h TTL mirrors PMS-136's PORTAL_SETUP_TOKEN_TTL_HOURS. Deliberately
        // shorter than the pre-554 7-day users-welcome window: the portal
        // path is what agents already use when flipping is_portal_user, so
        // both entry points share one operator-facing "how long is a portal
        // setup link good for?" answer.
        let expires_at = Utc::now() + Duration::hours(72);

        let mut tx = match self.db.begin_with_tenant(tenant_id).await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    contact_id = %contact_id,
                    error = ?e,
                    "MAPPS-554: begin_with_tenant failed while minting portal setup token",
                );
                return;
            }
        };
        let insert = sqlx::query(
            r#"
            INSERT INTO portal_setup_tokens (tenant_id, contact_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await;
        if let Err(e) = insert {
            tracing::warn!(
                tenant_id = %tenant_id,
                contact_id = %contact_id,
                error = ?e,
                "MAPPS-554: failed to insert portal_setup_tokens row",
            );
            return;
        }
        if let Err(e) = tx.commit().await {
            tracing::warn!(
                tenant_id = %tenant_id,
                contact_id = %contact_id,
                error = ?e,
                "MAPPS-554: commit failed on portal_setup_tokens tx",
            );
            return;
        }

        // MAPPS-649: build against the single portal-serving origin
        // (typically `https://portal.<apex>`, dev `http://localhost:4301`).
        // Retires the pre-649 per-tenant `<slug><suffix>` shape (see
        // git log for MAPPS-554's port-in-dev workaround, no longer
        // needed since the origin now carries its port verbatim).
        // `tenant_slug` is unused in the URL now; the visitor enters
        // their Company ID at step 1 or lands directly on
        // `/portal/set-password?token=...` when following the emailed
        // link. Kept as a parameter for the audit-log context below.
        let _ = tenant_slug;
        let portal_base = portal_base.trim_end_matches('/');
        let setup_link = format!("{portal_base}/portal/set-password?token={token}");
        let client_portal_url = portal_base.to_string();

        let display_name = match (admin_first_name.trim(), admin_last_name.trim()) {
            ("", "") => String::new(),
            (f, "") => f.to_string(),
            ("", l) => l.to_string(),
            (f, l) => format!("{f} {l}"),
        };
        let context = serde_json::json!({
            "recipient_contact_id": contact_id.to_string(),
            "recipient_email": admin_email,
            "display_name": display_name,
            "setup_link": setup_link,
            "client_portal_url": client_portal_url,
        });
        // SAFETY (PMS-261): `tenant_id` is the tenant we just provisioned
        // (create path) or resolved (resend path); `from_trusted` bridges
        // into the typed scope, and `dispatch` sets the GUC per query via
        // `begin_with_tenant`.
        match notify
            .dispatch(TenantId::from_trusted(tenant_id), "auth.welcome", &context)
            .await
        {
            Ok(_) => {
                // MAPPS-559: log the emitted setup_link so an operator
                // troubleshooting "This link is expired or invalid"
                // can eyeball whether the URL that shipped matches
                // what the customer clicked. The token embedded in
                // the URL is single-use; logging it is fine (a leak
                // is no worse than the leak that already happens by
                // emailing it).
                tracing::info!(
                    tenant_id = %tenant_id,
                    contact_id = %contact_id,
                    setup_link = %setup_link,
                    "MAPPS-554: portal admin welcome email queued via notifications dispatcher",
                );
            }
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    contact_id = %contact_id,
                    error = ?e,
                    "MAPPS-554: welcome dispatch failed; portal setup token persisted but no message queued",
                );
            }
        }
    }

    /// MAPPS-448 / MAPPS-554: re-issue the tenant portal admin's setup
    /// token and re-send the `auth.welcome` email. Super-admin path,
    /// invoked when the original mail went missing (SMTP outage,
    /// wrong-address typo caught later, admin lost the email) and the
    /// portal admin contact has not redeemed yet.
    ///
    /// Post-MAPPS-554 the identity a tenant is provisioned around is a
    /// portal admin CONTACT (`is_portal_user = true`, `portal_role =
    /// 'admin'`), NOT a `users` row. Steps:
    ///
    /// 1. Resolve the tenant's single portal-admin contact; 404 if
    ///    absent (pre-554 tenants that still hold a `users` row for
    ///    the admin follow the pre-554 users-side path via
    ///    `AuthService::resend_user_welcome` - not covered here).
    /// 2. 409 if the admin has already redeemed
    ///    (`portal_password_hash IS NOT NULL`) - a resend against an
    ///    active portal account would be a mystery mail from the
    ///    caller's perspective and a security-adjacent surface
    ///    (super-admin forcing a portal-setup link to someone else's
    ///    inbox).
    /// 3. Invalidate every unredeemed `portal_setup_tokens` row for
    ///    that contact so the old email's link stops working.
    /// 4. Audit an `Update` on the contacts row so the log names the
    ///    super-admin who re-issued the invite.
    /// 5. Mint + dispatch via [`mint_and_send_portal_welcome`], same
    ///    helper the create path uses.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn resend_admin_welcome(&self, tenant_id: TenantId, ctx: &AuditCtx) -> AppResult<()> {
        // Cross-tenant super-admin read against the RLS-protected `contacts`
        // table: run under the tenant GUC so the SELECT sees the row.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Merge cleanup: box the large variant in a follow-up (out of scope for the route-overlap fix)
        #[allow(clippy::type_complexity)]
        let admin: Option<(Uuid, Option<String>, String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, email, first_name, last_name, portal_password_hash FROM contacts \
                 WHERE tenant_id = $1 AND is_portal_user = TRUE AND portal_role = 'admin' \
                 ORDER BY created_at LIMIT 1",
        )
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((contact_id, admin_email_opt, admin_first_name, admin_last_name, pw_hash)) = admin
        else {
            return Err(AppError::not_found(
                "No portal admin contact found for this tenant",
            ));
        };
        let Some(admin_email) = admin_email_opt.filter(|s| !s.trim().is_empty()) else {
            return Err(AppError::conflict(
                "Portal admin contact has no email on file; cannot resend welcome",
            ));
        };
        if pw_hash.is_some() {
            return Err(AppError::conflict(
                "Portal admin has already activated their account; no resend needed",
            ));
        }
        // Slug is on the RLS-exempt `tenants` root row, but reading it under
        // the same tenant GUC is fine; keeps this in one tx.
        let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
            .bind(*tenant_id)
            .fetch_one(&mut *tx)
            .await?;
        // Invalidate any prior unredeemed portal setup link so only the
        // freshly emailed one works. Redeemed rows are deleted at redeem
        // time (see PMS-136 flow) so this DELETE is bounded to at most a
        // handful of pending tokens.
        sqlx::query("DELETE FROM portal_setup_tokens WHERE tenant_id = $1 AND contact_id = $2")
            .bind(*tenant_id)
            .bind(contact_id)
            .execute(&mut *tx)
            .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(contact_id),
            None,
            None,
        )
        .await?;
        tx.commit().await?;

        // mint_and_send_portal_welcome is best-effort: on dispatch failure
        // the token is committed but the mail is not queued (same posture
        // as the create path). A follow-up resend can be triggered.
        self.mint_and_send_portal_welcome(
            *tenant_id,
            contact_id,
            &admin_email,
            &admin_first_name,
            &admin_last_name,
            &slug,
        )
        .await;
        Ok(())
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
        // PMS-777: this runs on the per-request bunyip auth path
        // (place_bunyip_user). "Cheap" still meant three round-trip-bearing
        // probes on every authenticated request, forever, for a condition that
        // flips at most once per tenant. Memoize the Ok answer in process so a
        // tenant is probed once per TTL instead of once per request; a tenant
        // this process has not seen still runs the full guarded path below.
        if self.seeded_tenants.get(&tenant_id).await.is_some() {
            return Ok(());
        }
        self.seed_default_config(tenant_id).await?;
        self.seeded_tenants.insert(tenant_id, ()).await;
        Ok(())
    }

    /// The guarded seeding itself, split out of [`Self::ensure_default_config`]
    /// so the PMS-777 memo wraps exactly one success path.
    async fn seed_default_config(&self, tenant_id: Uuid) -> AppResult<()> {
        // The already-seeded case stays cheap on its own terms too: a couple of
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
        // MAPPS-457: rename collision guard. Same case-insensitive
        // "non-personal-only" scope as create_tenant, plus `id != $2`
        // so re-submitting the same name against the same row is a
        // no-op (idempotent, not a conflict against self).
        if let Some(new_name) = request.name.as_deref() {
            let collision: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tenants \
                 WHERE LOWER(name) = LOWER($1) AND id != $2 AND personal_owner_id IS NULL)",
            )
            .bind(new_name)
            .bind(tenant_id)
            .fetch_one(self.db.migrator_pool())
            .await?;
            if collision {
                return Err(AppError::conflict("A tenant with this name already exists"));
            }
        }

        // MAPPS-449: normalise + validate the requested slug BEFORE the
        // dynamic query builder runs. Slugify collapses casing / spaces /
        // punctuation the same way create_tenant does, then the uniqueness
        // probe rejects a collision with any OTHER tenant. `WHERE ... AND
        // id != $2` scopes the probe to peer rows, so re-submitting the
        // same slug is a no-op (idempotent, not a conflict against self).
        // Empty-post-slugify is a 400 because the extractor at
        // PortalHostConfig::extract_slug refuses empty labels.
        let normalized_slug = if let Some(raw) = request.slug.as_deref() {
            let candidate = slugify(raw);
            if candidate.is_empty() {
                return Err(AppError::validation_field(
                    "slug",
                    "must contain at least one URL-safe character",
                ));
            }
            let collision: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1 AND id != $2)",
            )
            .bind(&candidate)
            .bind(tenant_id)
            .fetch_one(self.db.migrator_pool())
            .await?;
            if collision {
                return Err(AppError::conflict("A tenant with this slug already exists"));
            }
            Some(candidate)
        } else {
            None
        };

        let mut query = String::from("UPDATE tenants SET updated_at = NOW()");
        let mut param_idx = 2;

        if request.name.is_some() {
            query.push_str(&format!(", name = ${}", param_idx));
            param_idx += 1;
        }
        if normalized_slug.is_some() {
            query.push_str(&format!(", slug = ${}", param_idx));
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
        // PMS-776: check the document before it is merged. These keys are read
        // by a client, not by us: three of them compose the contact sentence in
        // a client's email and `logo_url` becomes an `<img src>` in the same
        // message, so a malformed value is one the MSP appears to have
        // published. Includes the PMS-758 object check.
        if let Some(branding) = request.branding.as_ref() {
            validate_branding_patch(branding)?;
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
        if let Some(ref slug) = normalized_slug {
            query_builder = query_builder.bind(slug);
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

    /// MAPPS-450 / MAPPS-554: read the tenant admin's identity row for the
    /// tenant management modal. Post-554 the identity is a portal admin
    /// CONTACT (`is_portal_user = true`, `portal_role = 'admin'`), not
    /// a `users` row, so the read pivots to `contacts` and derives
    /// pending/active from `portal_password_hash IS NULL`. `TenantAdminInfo`
    /// stays wire-compatible: its `user_id` field is now the contact_id
    /// (see the type's docstring).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_tenant_admin(&self, tenant_id: TenantId) -> AppResult<TenantAdminInfo> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // MAPPS-554: `email` is Option<String> on contacts (nullable
        // column) but TenantAdminInfo.email is String; fill an empty
        // string when absent (the update path 400s empty email inputs
        // so the round-trip is safe).
        // Merge cleanup: box the large variant in a follow-up (out of scope for the route-overlap fix)
        #[allow(clippy::type_complexity)]
        let admin: Option<(Uuid, Option<String>, String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, email, first_name, last_name, portal_password_hash FROM contacts \
             WHERE tenant_id = $1 AND is_portal_user = TRUE AND portal_role = 'admin' \
             ORDER BY created_at LIMIT 1",
        )
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((contact_id, email_opt, first_name, last_name, pw_hash)) = admin else {
            return Err(AppError::not_found(
                "No portal admin contact found for this tenant",
            ));
        };
        // MAPPS-554: `status` is derived - pending until the portal
        // password is set, active thereafter. Matches the pre-554
        // users.status semantics as far as the UI cares (email
        // editable + resend affordance both gate on 'pending').
        let status = if pw_hash.is_some() {
            "active".to_string()
        } else {
            "pending".to_string()
        };
        Ok(TenantAdminInfo {
            user_id: contact_id,
            email: email_opt.unwrap_or_default(),
            first_name,
            last_name,
            status,
        })
    }

    /// MAPPS-450 / MAPPS-554: super-admin edits the tenant portal admin's
    /// email + name pair.
    ///
    /// Guards:
    /// - Empty request (nothing to change and `resend_welcome=false`) -> 400.
    ///   Prevents a stray audit-write for a no-op call.
    /// - Email change on `users.status = 'active'` -> 409. The admin has
    ///   already redeemed and is signing in; renaming their inbox is a
    ///   hijack surface the super-admin does not own. Copy points them at
    ///   the tenant admin's own Settings for a self-serve change.
    /// - Name changes are allowed at any status; they carry no auth impact.
    ///
    /// After the field updates commit, if `resend_welcome == true` AND the
    /// admin is still `pending`, delegates to [`resend_admin_welcome`] so
    /// the new email address receives a fresh setup link and any prior
    /// unredeemed token is invalidated. The client sets this flag when the
    /// email field is dirty; on name-only edits the resend is skipped.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_tenant_admin(
        &self,
        tenant_id: TenantId,
        request: &UpdateTenantAdminRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TenantAdminInfo> {
        let has_any_change =
            request.email.is_some() || request.first_name.is_some() || request.last_name.is_some();
        if !has_any_change && !request.resend_welcome {
            return Err(AppError::validation_field(
                "email",
                "at least one field must be supplied",
            ));
        }

        // MAPPS-554: the admin identity lives on `contacts` now
        // (is_portal_user=true, portal_role='admin'), not `users`.
        // Load current row + status guard, all under the tenant GUC
        // so the SELECT sees the row and any subsequent UPDATE +
        // audit-write on the same tx share the scope.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT id, email, portal_password_hash FROM contacts \
             WHERE tenant_id = $1 AND is_portal_user = TRUE AND portal_role = 'admin' \
             ORDER BY created_at LIMIT 1",
        )
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((admin_id, current_email_opt, pw_hash)) = existing else {
            return Err(AppError::not_found(
                "No portal admin contact found for this tenant",
            ));
        };
        let current_email = current_email_opt.unwrap_or_default();
        let current_status = if pw_hash.is_some() {
            "active".to_string()
        } else {
            "pending".to_string()
        };

        let email_changed = request
            .email
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|e| !e.eq_ignore_ascii_case(&current_email));
        if email_changed && current_status == "active" {
            return Err(AppError::conflict(
                "This tenant admin has already activated their account; the admin themselves must change their own email from Settings.",
            ));
        }

        // Snapshot before, apply the dynamic UPDATE, snapshot after, then
        // audit_write - same shape create_tenant uses. Each optional field
        // becomes a `COALESCE`-shaped ternary so callers can send just the
        // fields that changed without threading a builder.
        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(c) FROM contacts c WHERE id = $1")
                .bind(admin_id)
                .fetch_optional(&mut *tx)
                .await?;

        if has_any_change {
            sqlx::query(
                "UPDATE contacts SET \
                 email = COALESCE($2, email), \
                 first_name = COALESCE($3, first_name), \
                 last_name = COALESCE($4, last_name), \
                 updated_at = NOW() \
                 WHERE id = $1",
            )
            .bind(admin_id)
            .bind(
                request
                    .email
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty()),
            )
            .bind(
                request
                    .first_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty()),
            )
            .bind(
                request
                    .last_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty()),
            )
            .execute(&mut *tx)
            .await?;
        }

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(c) FROM contacts c WHERE id = $1")
                .bind(admin_id)
                .fetch_optional(&mut *tx)
                .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(admin_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        // Resend after commit so the token invalidation + re-send happens
        // against the freshly-written email address. `resend_admin_welcome`
        // 409s if status != 'pending', so a caller that flipped the flag
        // by mistake (e.g. edit-name-only) gets a soft rejection rather
        // than a mail queued to no purpose.
        if request.resend_welcome {
            if let Err(e) = self.resend_admin_welcome(tenant_id, ctx).await {
                match e {
                    AppError::Conflict(_) => {
                        // Admin is no longer pending; the field update
                        // still committed. Log but do not fail the call.
                        tracing::info!(
                            tenant_id = %tenant_id,
                            admin_id = %admin_id,
                            "update_tenant_admin: skipped resend, admin not pending",
                        );
                    }
                    other => return Err(other),
                }
            }
        }

        self.get_tenant_admin(tenant_id).await
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
        //
        // Doubles as the un-cancel path (MAPPS-558): any non-active
        // status flips back to 'active' here, so an operator who
        // clicks Reactivate on a Cancelled row gets the same restore
        // shape as they do on a Suspended row.
        sqlx::query("UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(self.db.migrator_pool())
            .await?;

        Ok(())
    }

    /// MAPPS-558: cancel a client. Flips `tenants.status` to
    /// 'cancelled' (permitted by the CHECK constraint in migration
    /// 002). Portal middleware (MAPPS-557) 401s every subsequent
    /// request from that tenant's contacts on the next fetch.
    /// Reversible via `activate_tenant`.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn cancel_tenant(&self, tenant_id: TenantId) -> AppResult<()> {
        // SAFETY (PMS-285): super-admin tenant-lifecycle handler writing the
        // RLS-exempt `tenants` root row by id. Migrator pool.
        sqlx::query("UPDATE tenants SET status = 'cancelled', updated_at = NOW() WHERE id = $1")
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

        // MAPPS-562: exclude the hidden system attribution users row
        // from the operator-facing user count so a fresh tenant with no
        // human users still reports zero, not one.
        let user_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users \
             WHERE tenant_id = $1 AND email NOT LIKE 'system+%@mokosh.local'",
        )
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

        // PMS-957: the cast is load-bearing. Postgres `SUM(bigint)` returns
        // NUMERIC, so decoding it as `i64` fails - and it failed on an EMPTY
        // table too, because `COALESCE` types its zero to match. This endpoint
        // therefore 500'd for every tenant since it was written, which is why
        // nobody noticed the figure it was trying to report was also always
        // zero: nothing ever got a number back to disbelieve.
        let storage_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(file_size), 0)::bigint FROM files WHERE tenant_id = $1",
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
    /// mokosh-contact-login prompt 002: seed the three built-in
    /// portal roles for a freshly provisioned tenant.
    ///
    /// Called by `create_tenant` after the tenant + own_company are in
    /// place. Idempotent via the partial-unique index the seed rows
    /// land in (`portal_roles_tenant_wide_name_uniq`, migration 148:
    /// `(tenant_id, LOWER(name)) WHERE company_id IS NULL`), so a
    /// re-run (or a race with migration 142's backfill against this
    /// tenant) collapses cleanly. PMS-929 (prompt 012) moved from the
    /// plain `UNIQUE (tenant_id, name)` migration 139 carried to this
    /// partial-index shape so a Company-scoped role can share a name
    /// with a tenant-wide one; the ON CONFLICT clause now targets the
    /// partial index explicitly. Mirrors the capability sets in
    /// migration 142 exactly; the `all_capabilities_match_seed_migration`
    /// test in `contact_portal::capabilities` guards drift.
    ///
    /// SAFETY (PMS-285): runs under the new tenant's GUC tx so the
    /// `portal_roles` RLS WITH CHECK policy sees `app.current_tenant`.
    pub async fn seed_builtin_portal_roles(&self, tenant_id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO portal_roles (tenant_id, name, capabilities, is_builtin)
            VALUES
                ($1, 'Billing Contact',
                 ARRAY['invoices:read', 'invoices:pay', 'quotes:read', 'quotes:accept',
                       'notifications:read', 'settings:manage_own'], TRUE),
                ($1, 'Support Contact',
                 ARRAY['tickets:read', 'tickets:write', 'tickets:comment', 'kb:read',
                       'notifications:read', 'settings:manage_own'], TRUE),
                ($1, 'Read-Only',
                 ARRAY['tickets:read', 'invoices:read', 'quotes:read', 'contracts:read',
                       'assets:read', 'projects:read', 'kb:read', 'notifications:read'], TRUE)
            ON CONFLICT (tenant_id, LOWER(name)) WHERE company_id IS NULL DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

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

        // PMS-943: timesheets are the one module whose starting value is not the
        // default tenant's. Copying it would give every self-signed-up personal
        // tenant the default tenant's `org` answer, which is the submit-a-week-
        // to-yourself flow this feature exists to remove. It is read off the new
        // tenant's own `kind` instead, and written after the copy so it wins.
        //
        // An UPDATE, not an upsert: the copy above supplies the row, because
        // migration 120 gives the default tenant one. Should that ever stop
        // being true, no row means the module is off, which is the safe answer
        // for a tenant whose kind could not be consulted.
        sqlx::query(
            r#"
            UPDATE module_config mc
            SET is_enabled = (t.kind = 'org'), updated_at = NOW()
            FROM tenants t
            WHERE t.id = mc.tenant_id
              AND mc.tenant_id = $1
              AND mc.module_name = 'timesheets'
            "#,
        )
        .bind(new_tenant_id)
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
                                 'ticket.note_added',
                                 -- PMS-918 (mokosh-contact-login prompt 010):
                                 -- the two-block grant email (magic-link
                                 -- primary + set-password secondary). Seeded
                                 -- for the default tenant by migration 144;
                                 -- copied here so a tenant created after 010
                                 -- can dispatch a grant email at all.
                                 'auth.portal_grant',
                                 -- PMS-918 followup: the recurring-sign-in
                                 -- magic-link email fired by
                                 -- ContactAuthService::request_login_link
                                 -- (the /portal/login finder page). Seeded
                                 -- for the default tenant by migration 149;
                                 -- copied here so a new tenant's contacts can
                                 -- request a sign-in link and actually receive
                                 -- one instead of a silent no-op.
                                 'auth.login_link')
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
                                   'forms.request_link', 'ticket.note_added',
                                   -- PMS-918 (mokosh-contact-login prompt 010):
                                   -- pair the auth.portal_grant template above
                                   -- with its rule so grant dispatch fans out.
                                   'auth.portal_grant',
                                   -- PMS-918 followup: pair auth.login_link so
                                   -- the recurring-sign-in magic-link email
                                   -- actually fans out. A template with no rule
                                   -- is a message that is never sent.
                                   'auth.login_link')
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

    // PMS-836: compose.dev.yml forwards this key with an empty default, so
    // "set but empty" has to mean the same as unset.
    #[test]
    fn an_empty_seed_tenant_id_falls_back_to_the_migration_seed() {
        for raw in [None, Some(""), Some("   ")] {
            assert_eq!(
                parse_seed_source_tenant_id(raw).unwrap(),
                Uuid::from_u128(1),
                "{raw:?} must read as unset"
            );
        }
    }

    #[test]
    fn a_malformed_seed_tenant_id_is_a_configuration_error() {
        assert!(parse_seed_source_tenant_id(Some("not-a-uuid")).is_err());
    }

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
