//! New-account demo-data seeding (PMS-157, PMS-710).
//!
//! On the first authenticated visit by any tenant, seed a small but connected
//! set of illustrative PSA rows (two companies, four contacts, one service SLA,
//! two projects, five tickets - see [`super::data`]) so a fresh account shows
//! how Mokosh's objects relate instead of an empty shell. Triggered lazily from
//! [`super::middleware::seed_middleware`] rather than at account creation,
//! because Bunyip users JIT-land in a pre-existing tenant and never pass through
//! `TenantService::create_tenant`.
//!
//! PMS-710: the automatic path runs in PRODUCTION only. Every new production
//! signup gets their own personal tenant (PMS-244) and this seeds it; staging is
//! the shared demo environment and is kept clean (seeds nothing), and other
//! environments seed nothing unless a developer opts in. See [`demo_seed_enabled`].
//!
//! Seeding is **best-effort and never blocks a request**: the middleware
//! spawns it detached and any failure is logged, not surfaced. Three guards
//! keep it correct and cheap:
//!
//! 1. An in-process `seen` set short-circuits every request after the first
//!    confirmation, so the steady state touches no database.
//! 2. An atomic compare-and-set on `tenants.settings->>'demo_seeded'` claims
//!    the seed exactly once, even under a burst of concurrent first requests
//!    (only the request that flips the flag proceeds).
//! 3. An emptiness check skips tenants that already have companies, so an
//!    established tenant that predates this feature is never polluted on the
//!    first visit after a deploy (the flag is still set so we stop checking).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use crate::modules::auth::TenantId;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::AuditCtx;
use crate::modules::contacts::ContactService;
use crate::modules::projects::{CreateTaskRequest, ProjectsService};
use crate::modules::sla::SlaService;
use crate::modules::tickets::TicketService;
use crate::utils::error::AppResult;

use super::data::{demo_companies, demo_contacts, demo_projects, demo_sla, demo_tickets};

/// Whether the automatic first-visit demo seed runs in this deployment (PMS-710).
///
/// Production seeds every new account so a fresh signup has example PSA data to
/// explore. Every other environment (staging, dev, test) seeds NOTHING by
/// default: staging is the shared demo environment where people log in to see
/// the real, current app, so it is kept clean; a developer can still opt in
/// locally with `MOKOSH_DEMO_SEED=true`. Read once from `ENVIRONMENT` (the same
/// var `AppConfig` reads) plus the optional override.
///
/// This gates only the automatic path. The explicit admin "Load demo data"
/// action ([`SeedService::load_demo_data`]) is an operator choice and is NOT
/// gated here. The shared multi-user landing tenant is also excluded separately
/// and unconditionally by [`shared_landing_tenant`] (PMS-239). To remove demo
/// rows seeded before this, run `scripts/wipe_demo_seed.sql`.
fn demo_seed_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let environment =
            std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        seed_enabled_for(
            &environment,
            std::env::var("MOKOSH_DEMO_SEED").ok().as_deref(),
        )
    })
}

/// The pure gate decision (PMS-710), split out so it is unit-testable without
/// process env or the `OnceLock` memoization: production always seeds; every
/// other environment seeds only when the `MOKOSH_DEMO_SEED` override is an
/// explicit truthy value.
fn seed_enabled_for(environment: &str, override_flag: Option<&str>) -> bool {
    if environment.trim().eq_ignore_ascii_case("production") {
        return true;
    }
    matches!(
        override_flag.map(|v| v.trim().to_ascii_lowercase()),
        Some(v) if matches!(v.as_str(), "1" | "true" | "yes" | "on")
    )
}

/// The shared multi-user landing tenant, if this deployment funnels users
/// into one (PMS-239). Bunyip-issued tokens carry no tenant claim yet, so
/// every OIDC user JIT-lands in `OIDC_DEFAULT_TENANT_ID` (see
/// `auth::middleware::ensure_user_from_bunyip` / docs §3.3). That tenant is a
/// shared zone, NOT a fresh single-owner account, so it must never be
/// auto-seeded with per-account demo data - otherwise every user sees (and can
/// edit) the same demo rows, which is exactly the bug reported in PMS-239.
///
/// Returns `None` when the env var is unset (single-tenant / test / legacy
/// deployments), in which case there is no shared tenant to exclude.
fn shared_landing_tenant() -> Option<Uuid> {
    std::env::var("OIDC_DEFAULT_TENANT_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

/// Outcome of an explicit, admin-triggered demo-data load
/// ([`SeedService::load_demo_data`], PMS-679). Distinct from the best-effort
/// auto-seed, which returns nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadDemoOutcome {
    /// Demo rows were inserted (the tenant was empty).
    Seeded,
    /// The tenant already had business data; nothing was inserted.
    AlreadyHasData,
}

/// Seeds first-visit demo data for new accounts. Cheap to clone (holds
/// `Arc`/`Clone` services and a shared seen-set).
#[derive(Clone)]
pub struct SeedService {
    db: Database,
    contacts: ContactService,
    tickets: TicketService,
    projects: ProjectsService,
    sla: SlaService,
    /// Tenants this process has already settled (seeded, skipped, or
    /// confirmed-claimed-elsewhere). Bounds DB work to once per tenant per
    /// process lifetime.
    seen: Arc<Mutex<HashSet<Uuid>>>,
    /// The shared multi-user landing tenant to never auto-seed (PMS-239).
    /// Captured at construction from `OIDC_DEFAULT_TENANT_ID`.
    shared_tenant: Option<Uuid>,
    /// Whether the automatic first-visit seed runs here (PMS-710). Captured at
    /// construction from [`demo_seed_enabled`] (environment + override) so the
    /// process reads the env once; tests pin it via [`Self::with_seed_enabled`].
    enabled: bool,
}

impl SeedService {
    pub fn new(
        db: Database,
        contacts: ContactService,
        tickets: TicketService,
        projects: ProjectsService,
        sla: SlaService,
    ) -> Self {
        Self {
            db,
            contacts,
            tickets,
            projects,
            sla,
            seen: Arc::new(Mutex::new(HashSet::new())),
            shared_tenant: shared_landing_tenant(),
            enabled: demo_seed_enabled(),
        }
    }

    /// Override whether the automatic first-visit seed runs, independent of the
    /// process environment. Lets tests exercise both the production (on) and
    /// staging (off) gate without racing on process-global env + `OnceLock`.
    pub fn with_seed_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Override the shared landing tenant explicitly. Lets callers (and tests)
    /// pin the tenant to exclude without depending on process-global env state.
    pub fn with_shared_tenant(mut self, tenant_id: Option<Uuid>) -> Self {
        self.shared_tenant = tenant_id;
        self
    }

    /// True once this process has settled `tenant_id` (no further DB work
    /// needed). The lock is held only for the lookup, never across an await.
    pub fn is_seen(&self, tenant_id: Uuid) -> bool {
        self.seen
            .lock()
            .map(|s| s.contains(&tenant_id))
            .unwrap_or(false)
    }

    fn mark_seen(&self, tenant_id: Uuid) {
        if let Ok(mut s) = self.seen.lock() {
            s.insert(tenant_id);
        }
    }

    /// Ensure the tenant has demo data, seeding it on the first visit.
    /// Best-effort: all errors are logged and swallowed so a seeding
    /// problem can never break the request that triggered it.
    pub async fn ensure_demo_seeded(&self, tenant_id: Uuid, user_id: Uuid) {
        if !self.enabled || self.is_seen(tenant_id) {
            return;
        }
        // PMS-239: never auto-seed the shared multi-user landing tenant. It is
        // not a fresh single-owner account - every Bunyip user lands there - so
        // demo rows would be shared by, and editable across, all of them. Mark
        // it seen so we skip the check on every future request this process
        // serves.
        if self.shared_tenant == Some(tenant_id) {
            self.mark_seen(tenant_id);
            tracing::debug!(%tenant_id, "skipping demo seed for shared landing tenant");
            return;
        }
        match self.run(tenant_id, user_id).await {
            Ok(seeded) => {
                self.mark_seen(tenant_id);
                if seeded {
                    tracing::info!(%tenant_id, "seeded demo data for new account");
                }
            }
            Err(e) => {
                // Do NOT mark seen: a transient DB error (e.g. the claim
                // query itself failed) should be retried on a later request.
                // The flag claim is idempotent, so a retry can never
                // double-seed. A failure AFTER the claim succeeded leaves the
                // flag set, so the retry simply observes "already claimed" and
                // settles without inserting anything.
                tracing::warn!(error = %e, %tenant_id, "demo seeding failed; will retry on next request");
            }
        }
    }

    /// Load demo data on explicit admin request (the Settings -> Data "Load
    /// demo data" button, PMS-679). Additive and non-destructive: it seeds
    /// only when the tenant has no business data, and never wipes. Unlike
    /// [`Self::ensure_demo_seeded`] - the best-effort first-visit auto-seed
    /// that swallows its result - this surfaces the outcome so the UI can
    /// report "loaded" vs. "already has data".
    ///
    /// Refuses the shared multi-user landing tenant (PMS-239) exactly as the
    /// auto-seed does. On a successful load it also claims the `demo_seeded`
    /// flag and marks the in-process `seen` set, so the first-visit auto-seed
    /// stays a no-op for this tenant afterwards. It does NOT consult the
    /// `MOKOSH_DEMO_SEED` kill-switch: that governs the automatic first-visit
    /// path, whereas this is an explicit operator action.
    pub async fn load_demo_data(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<LoadDemoOutcome> {
        // PMS-239: the shared landing zone is never a single-owner account, so
        // it must never receive per-account demo rows.
        if self.shared_tenant == Some(tenant_id) {
            return Ok(LoadDemoOutcome::AlreadyHasData);
        }
        // Additive: only an empty tenant is seeded; an established one is left
        // untouched (no wipe).
        if self.tenant_has_companies(tenant_id).await? {
            return Ok(LoadDemoOutcome::AlreadyHasData);
        }
        self.seed_rows(tenant_id, user_id).await?;
        // Keep the auto-seed bookkeeping consistent so the middleware never
        // re-seeds this tenant: claim the flag (best-effort) and mark it seen.
        let _ = self.try_claim(tenant_id).await;
        self.mark_seen(tenant_id);
        Ok(LoadDemoOutcome::Seeded)
    }

    /// Returns `Ok(true)` when demo rows were inserted, `Ok(false)` when the
    /// tenant was already claimed or already had data.
    async fn run(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        if !self.try_claim(tenant_id).await? {
            // Another request (this process or another) already claimed the
            // seed for this tenant.
            return Ok(false);
        }
        if self.tenant_has_companies(tenant_id).await? {
            // Pre-existing tenant: the flag is now set so we stop checking,
            // but we must not inject demo rows into an account that already
            // has real data.
            tracing::debug!(%tenant_id, "tenant already has data; marked demo_seeded without inserting");
            return Ok(false);
        }
        self.seed_rows(tenant_id, user_id).await?;
        Ok(true)
    }

    /// Atomically flip `tenants.settings->>'demo_seeded'` from unset/false to
    /// true. Returns `Ok(true)` iff this call won the claim. A missing tenant
    /// row (no match) returns `Ok(false)`.
    async fn try_claim(&self, tenant_id: Uuid) -> AppResult<bool> {
        let claimed: Option<Uuid> = sqlx::query_scalar(
            r#"UPDATE tenants
               SET settings = jsonb_set(
                       COALESCE(settings, '{}'::jsonb),
                       '{demo_seeded}', 'true'::jsonb, true),
                   updated_at = NOW()
               WHERE id = $1
                 AND COALESCE((settings->>'demo_seeded')::boolean, false) = false
               RETURNING id"#,
        )
        .bind(tenant_id)
        // SAFETY (PMS-285 / PMS-692): the demo-seed claim flips a flag on the
        // caller's own `tenants` row. `tenants` is the RLS-exempt isolation root
        // (migration 038), so this is safe on the app pool with no GUC; the
        // per-tenant seed writes that follow set the tenant GUC via
        // `begin_with_tenant`.
        .fetch_optional(self.db.pool())
        .await?;
        Ok(claimed.is_some())
    }

    async fn tenant_has_companies(&self, tenant_id: Uuid) -> AppResult<bool> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM companies WHERE tenant_id = $1 \
                 AND company_type <> 'internal')",
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        Ok(exists)
    }

    /// Insert the connected demo dataset (SLA, companies, contacts, projects,
    /// tickets) through the real service create paths, in FK-dependency order.
    /// Audit rows are attributed to the visiting user (PMS-710).
    ///
    /// SAFETY (PMS-139/PMS-285): the demo seeder is a trusted system actor that
    /// seeds a known tenant id (claimed via `try_claim` in `run`, or an
    /// emptiness-checked tenant in `load_demo_data`), not user input, so every
    /// call bridges into the tenant-scoped services through
    /// `TenantId::from_trusted`.
    async fn seed_rows(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<()> {
        let ctx = AuditCtx {
            tenant_id: Some(tenant_id),
            user_id: Some(user_id),
            ip: None,
            user_agent: None,
        };
        let tenant = TenantId::from_trusted(tenant_id);

        // 1. Service SLA policy first - it has no dependencies, and the company
        //    plus some tickets below link to it to show the relationship.
        let sla = self.sla.create_policy(tenant, &demo_sla(), &ctx).await?;

        // 2. Companies (the one at the bundle's sla.company_index carries sla_id).
        let mut company_ids = Vec::new();
        for req in demo_companies(sla.id) {
            let company = self.contacts.create_company(tenant, &req, &ctx).await?;
            company_ids.push(company.id);
        }

        // 3. Contacts, each linked to its company.
        let mut contact_ids = Vec::new();
        for req in demo_contacts(&company_ids) {
            let contact = self.contacts.create_contact(tenant, &req, &ctx).await?;
            contact_ids.push(contact.id);
        }

        // 4. Projects. The project is core (propagates on error); its phase and
        //    task are best-effort - a task needs a tenant task status, which a
        //    tenant provisioned without `copy_default_config` would lack.
        let task_status = self.existing_task_status_id(tenant_id).await.ok().flatten();
        for build in demo_projects(&company_ids, user_id) {
            let project = self
                .projects
                .create_project(tenant, &build.request, &ctx)
                .await?;
            let Some(phase_req) = build.phase else {
                continue;
            };
            let phase = match self
                .projects
                .create_project_phase(tenant, project.id, &phase_req, &ctx)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, %tenant_id, "demo project phase seeding skipped");
                    continue;
                }
            };
            if let (Some(title), Some(status_id)) = (build.task_title, task_status) {
                let task = CreateTaskRequest {
                    title,
                    description: Some("Example task - part of the demo project.".to_string()),
                    status_id,
                    phase_id: Some(phase.id),
                    parent_task_id: None,
                    priority: "medium".to_string(),
                    assigned_to_id: None,
                    estimated_hours: None,
                    start_date: None,
                    due_date: None,
                    sort_order: 0,
                };
                if let Err(e) = self
                    .projects
                    .create_task(tenant, project.id, &task, &ctx)
                    .await
                {
                    tracing::warn!(error = %e, %tenant_id, "demo task seeding skipped");
                }
            }
        }

        // 5. Tickets are best-effort per row. `create_ticket` requires the
        //    tenant's default status/priority/queue to exist; a tenant missing
        //    them (no `copy_default_config` / migration 023 seed) would error.
        //    That must not abort the whole seed and leave the account with no
        //    tickets, so a failing ticket is logged and skipped, not propagated.
        for ticket in demo_tickets(&company_ids, &contact_ids) {
            if let Err(e) = self
                .tickets
                .create_ticket(tenant, user_id, &ticket, &ctx)
                .await
            {
                tracing::warn!(error = %e, %tenant_id, "demo ticket seeding skipped");
            }
        }
        Ok(())
    }

    /// The tenant's first task status id, if it has any (`copy_default_config`
    /// seeds them). Returns `None` when the tenant has none, so the demo task is
    /// skipped rather than the whole seed failing - the seeder never creates
    /// config rows in a user's account.
    async fn existing_task_status_id(&self, tenant_id: Uuid) -> AppResult<Option<Uuid>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM task_statuses WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::seed_enabled_for;

    #[test]
    fn production_always_seeds() {
        // PMS-710: production seeds a new account regardless of the override,
        // including with the legacy `MOKOSH_DEMO_SEED=false` still in its config.
        assert!(seed_enabled_for("production", None));
        assert!(seed_enabled_for("production", Some("false")));
        assert!(seed_enabled_for("Production", Some("off")));
        assert!(seed_enabled_for(" production ", None));
    }

    #[test]
    fn staging_and_dev_seed_nothing_by_default() {
        // Staging is the shared demo environment and must stay clean; dev/test
        // also seed nothing unless a developer opts in.
        for env in ["staging", "development", "dev", "test", ""] {
            assert!(!seed_enabled_for(env, None), "{env} unset seeds nothing");
            assert!(
                !seed_enabled_for(env, Some("false")),
                "{env} =false seeds nothing"
            );
        }
    }

    #[test]
    fn non_production_honours_the_explicit_dev_override() {
        for flag in ["1", "true", "TRUE", "yes", "on"] {
            assert!(
                seed_enabled_for("development", Some(flag)),
                "dev override {flag} enables seeding"
            );
        }
        // The override never turns staging into a seeding environment via a
        // stray non-truthy value.
        assert!(!seed_enabled_for("staging", Some("maybe")));
    }
}
