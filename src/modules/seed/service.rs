//! New-account demo-data seeding (PMS-157).
//!
//! On the first authenticated visit by any tenant, seed a small set of
//! illustrative rows (one company, two contacts, three tickets) so a fresh
//! account shows how Mokosh works instead of an empty shell. Triggered
//! lazily from [`super::middleware::seed_middleware`] rather than at account
//! creation, because Bunyip users JIT-land in a pre-existing tenant and
//! never pass through `TenantService::create_tenant`.
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

use uuid::Uuid;
use crate::modules::auth::TenantId;

use crate::db::Database;
use crate::modules::audit::AuditCtx;
use crate::modules::contacts::ContactService;
use crate::modules::tickets::TicketService;
use crate::utils::error::AppResult;

use super::data::{demo_company, demo_contact_primary, demo_contact_secondary, demo_tickets};

/// Whether demo seeding is enabled. Reads `MOKOSH_DEMO_SEED` once;
/// defaults to enabled. Set it to `0`/`false`/`no`/`off` to disable in
/// environments where automatic demo rows are unwanted (e.g. E2E/staging
/// against the shared default tenant).
fn demo_seed_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("MOKOSH_DEMO_SEED")
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(true)
    })
}

/// Seeds first-visit demo data for new accounts. Cheap to clone (holds
/// `Arc`/`Clone` services and a shared seen-set).
#[derive(Clone)]
pub struct SeedService {
    db: Database,
    contacts: ContactService,
    tickets: TicketService,
    /// Tenants this process has already settled (seeded, skipped, or
    /// confirmed-claimed-elsewhere). Bounds DB work to once per tenant per
    /// process lifetime.
    seen: Arc<Mutex<HashSet<Uuid>>>,
}

impl SeedService {
    pub fn new(db: Database, contacts: ContactService, tickets: TicketService) -> Self {
        Self {
            db,
            contacts,
            tickets,
            seen: Arc::new(Mutex::new(HashSet::new())),
        }
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
        if !demo_seed_enabled() || self.is_seen(tenant_id) {
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
        .fetch_optional(self.db.pool())
        .await?;
        Ok(claimed.is_some())
    }

    async fn tenant_has_companies(&self, tenant_id: Uuid) -> AppResult<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM companies WHERE tenant_id = $1)")
                .bind(tenant_id)
                .fetch_one(self.db.pool())
                .await?;
        Ok(exists)
    }

    /// Insert the demo company, contacts, and tickets through the real
    /// service create paths. Audit rows are attributed to the visiting user.
    async fn seed_rows(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<()> {
        let ctx = AuditCtx {
            tenant_id: Some(tenant_id),
            user_id: Some(user_id),
            ip: None,
            user_agent: None,
        };

        // SAFETY (PMS-139): the demo seeder is a trusted system actor that
        // seeds a known tenant id (claimed via `try_claim` above), not user
        // input, so it bridges into the tenant-scoped contacts service through
        // `from_trusted`.
        let company = self
            .contacts
            .create_company(TenantId::from_trusted(tenant_id), &demo_company(), &ctx)
            .await?;
        let primary = self
            .contacts
            .create_contact(TenantId::from_trusted(tenant_id), &demo_contact_primary(company.id), &ctx)
            .await?;
        self.contacts
            .create_contact(TenantId::from_trusted(tenant_id), &demo_contact_secondary(company.id), &ctx)
            .await?;

        // Tickets are best-effort per row. `create_ticket` requires the
        // tenant's default status/priority/queue to exist; a tenant missing
        // them (no `copy_default_config` / migration 023 seed) would error.
        // That must not abort the whole seed and leave the account with NO
        // demo data - the company + contacts are the core of the demo - so a
        // failing ticket is logged and skipped rather than propagated.
        for ticket in demo_tickets(company.id, primary.id) {
            if let Err(e) = self
                .tickets
                .create_ticket(TenantId::from_trusted(tenant_id), user_id, &ticket, &ctx)
                .await
            {
                tracing::warn!(error = %e, %tenant_id, "demo ticket seeding skipped");
            }
        }
        Ok(())
    }
}
