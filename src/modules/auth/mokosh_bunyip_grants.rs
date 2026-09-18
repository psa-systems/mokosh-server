//! BUNYIP-674 [BUNYIP-626 child 3]: local mirror of Bunyip's mokosh grants.
//!
//! Bunyip is the authoritative source of grants; this module holds the
//! Mokosh-side mirror that lets a revoked grant take effect on the next
//! request rather than at the next `at+jwt` refresh.
//!
//! Two write paths land rows here, both driven from
//! `bunyip_webhook::mokosh_grant_changed`:
//!
//! - a `granted` event upserts the row with the current role and NULLs
//!   `revoked_at`. Duplicates are idempotent (a second `granted` event
//!   with the same triple leaves the row identical up to `updated_at`).
//! - a `revoked` event upserts with `revoked_at = NOW()` and drops the
//!   role to NULL. A `revoked` event for a triple Mokosh never saw a
//!   `granted` for is NOT an error - the row is inserted straight into
//!   the revoked state so a race where Mokosh missed the earlier
//!   `granted` webhook still lands in the correct end state.
//!
//! One read path: [`MokoshBunyipGrantService::is_grant_active`]. Reads
//! the migrator pool (BYPASSRLS) because the table is deliberately
//! cross-tenant - a grantee's row names an owner's tenant they do not
//! otherwise belong to (see `tests/rls_coverage.rs`'s
//! `ALLOWED_WITHOUT_RLS` note). Cached process-wide with a 30-second
//! TTL: the parent BUNYIP-674 ticket names 30s as the stale window, so
//! a miss triggers a single query, populates the cache, and the next
//! request in that process reads through it.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use mokosh_types::auth::UserRole;

/// BUNYIP-674 option B: project a grant role from Bunyip's PMS-1162
/// vocabulary (`admin` / `manager` / `technician` / `finance` /
/// `read_only`) onto Mokosh's [`UserRole`]. `None` on an unknown
/// value so the middleware refuses to place the caller rather than
/// silently granting one of the seven mokosh roles by accident.
///
/// MAPPS-877 (2026-09-18): `read_only` now projects onto the
/// first-class [`UserRole::ReadOnly`] variant that landed alongside
/// migration 225. Before this it deliberately mapped to
/// [`UserRole::Technician`] because mokosh had no read-only tier;
/// that gave every `read_only` grantee technician-level WRITE access
/// on the granted workspace, so a viewer could create companies,
/// invoices and tickets. `ReadOnly::can_write` returns false and
/// every mutating handler that carries the `RequireWriteAccess`
/// extractor refuses that role at the router boundary.
pub fn map_grant_role(vocab: &str) -> Option<UserRole> {
    match vocab {
        "admin" => Some(UserRole::Admin),
        "manager" => Some(UserRole::Manager),
        "technician" => Some(UserRole::Technician),
        "finance" => Some(UserRole::Finance),
        "read_only" => Some(UserRole::ReadOnly),
        _ => None,
    }
}

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::utils::error::AppResult;

/// How long a resolved `is_grant_active` answer stays cached. Matches the
/// stale-window budget the parent BUNYIP-674 ticket documents. A shorter
/// TTL is fine and self-defeating (the webhook is the primary
/// invalidation path); a longer TTL widens the parent's contract.
const GRANT_CACHE_TTL: Duration = Duration::from_secs(30);

/// A cache key: one Bunyip user, one Mokosh tenant slug.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GrantKey {
    grantee_bunyip_user_id: Uuid,
    mokosh_account_id: String,
}

/// The cached answer to `is_grant_active`.
///
/// `role` is `Some` on an active grant and `None` on a revoked one. The
/// receiver drops the role to NULL when it upserts the revoked row so
/// the value carried here mirrors the schema.
#[derive(Debug, Clone)]
struct GrantSnapshot {
    /// The role the grant was minted at, `None` when revoked. A future
    /// caller that reads role rather than boolean activeness (e.g. the
    /// `at+jwt` claim projection) reads this straight through.
    #[allow(dead_code)]
    role: Option<String>,
    /// True when the row exists AND `revoked_at IS NULL`.
    active: bool,
    /// When this snapshot was resolved. Compared against
    /// `GRANT_CACHE_TTL` on read.
    resolved_at: Instant,
}

/// Process-wide 30s TTL cache. Not a `moka` because the working set is
/// small (one entry per active (grantee, tenant) pair, evicted on TTL)
/// and adding a dep for this one call is out of scale.
static GRANT_CACHE: RwLock<Option<HashMap<GrantKey, GrantSnapshot>>> = RwLock::new(None);

/// Row shape returned by the `is_grant_active` query. Only the fields
/// the callers actually read are named.
#[derive(Debug, sqlx::FromRow)]
struct GrantRow {
    role: Option<String>,
    revoked_at: Option<DateTime<Utc>>,
}

pub struct MokoshBunyipGrantService;

impl MokoshBunyipGrantService {
    /// Whether the caller (`grantee_bunyip_user_id`) currently holds an
    /// active grant to the named Mokosh tenant. `false` covers both
    /// "no grant row" and "row present but revoked".
    ///
    /// Reads the process-wide 30s cache first; on a miss consults the
    /// database and populates the cache. A cache miss does not push a
    /// negative result (no row at all) into the cache: a future
    /// `granted` webhook then lands the positive answer without waiting
    /// for the negative to age out. A negative KNOWN (row exists with
    /// `revoked_at IS NOT NULL`) DOES cache, because a re-grant on
    /// Bunyip fires a `granted` webhook that invalidates this entry
    /// directly.
    pub async fn is_grant_active(
        pool: &PgPool,
        grantee_bunyip_user_id: Uuid,
        mokosh_account_id: &str,
    ) -> AppResult<bool> {
        let key = GrantKey {
            grantee_bunyip_user_id,
            mokosh_account_id: mokosh_account_id.to_string(),
        };

        if let Some(snapshot) = read_cache(&key) {
            if snapshot.resolved_at.elapsed() < GRANT_CACHE_TTL {
                return Ok(snapshot.active);
            }
        }

        // SAFETY (PMS-285 / PMS-692 shape): the table is cross-tenant
        // and RLS-exempt (see `tests/rls_coverage.rs`'s
        // `ALLOWED_WITHOUT_RLS`), so this read runs on the raw
        // NOBYPASSRLS pool without a GUC. `mokosh_app` holds SELECT on
        // it.
        let row: Option<GrantRow> = sqlx::query_as(
            "SELECT role, revoked_at FROM mokosh_bunyip_grants \
             WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
        )
        .bind(grantee_bunyip_user_id)
        .bind(mokosh_account_id)
        .fetch_optional(pool)
        .await?;

        let (role, active, cache) = match row {
            Some(r) => {
                let active = r.revoked_at.is_none() && r.role.is_some();
                (r.role, active, true)
            }
            None => (None, false, false),
        };

        if cache {
            write_cache(
                key,
                GrantSnapshot {
                    role,
                    active,
                    resolved_at: Instant::now(),
                },
            );
        }
        Ok(active)
    }

    /// BUNYIP-674 option B (phase 2): the ROLE the grant carries when
    /// it is active, `None` otherwise. Consults the same 30s cache
    /// [`Self::is_grant_active`] populates and never re-queries when
    /// that cache is warm - so the grant-scoped auth path, which asks
    /// both "is it active" and "which role" per request, pays for the
    /// DB read once.
    ///
    /// A revoked row returns `Ok(None)` for the same reason
    /// `is_grant_active` returns `false`: the caller reads the role
    /// only to project it as `AuthState.user.role`, and there is no
    /// role to project when the grant is not active.
    pub async fn active_grant_role(
        pool: &PgPool,
        grantee_bunyip_user_id: Uuid,
        mokosh_account_id: &str,
    ) -> AppResult<Option<String>> {
        let key = GrantKey {
            grantee_bunyip_user_id,
            mokosh_account_id: mokosh_account_id.to_string(),
        };
        if let Some(snapshot) = read_cache(&key) {
            if snapshot.resolved_at.elapsed() < GRANT_CACHE_TTL {
                return Ok(if snapshot.active { snapshot.role } else { None });
            }
        }
        let row: Option<GrantRow> = sqlx::query_as(
            "SELECT role, revoked_at FROM mokosh_bunyip_grants \
             WHERE grantee_bunyip_user_id = $1 AND mokosh_account_id = $2",
        )
        .bind(grantee_bunyip_user_id)
        .bind(mokosh_account_id)
        .fetch_optional(pool)
        .await?;
        let (role, active, cache) = match row {
            Some(r) => {
                let active = r.revoked_at.is_none() && r.role.is_some();
                (r.role, active, true)
            }
            None => (None, false, false),
        };
        if cache {
            write_cache(
                key,
                GrantSnapshot {
                    role: role.clone(),
                    active,
                    resolved_at: Instant::now(),
                },
            );
        }
        Ok(if active { role } else { None })
    }

    /// Idempotent UPSERT called from the webhook receiver. `role` is
    /// `Some` on a `granted` event and `None` on a `revoked` one; the
    /// CHECK constraint on the table pins the role-vs-revoked_at
    /// coupling so a webhook that ships an inconsistent pair fails at
    /// write time rather than reading back inconsistently.
    ///
    /// Every write invalidates the cache entry for the (grantee,
    /// account) pair so the next reader sees the fresh value without
    /// waiting for the TTL.
    #[allow(clippy::too_many_arguments)]
    /// PMS-1208 finding 3: 9-arg variant that also records the
    /// grantee's `grantee_email` (case-insensitively indexed on the
    /// mirror in migration 224). The accept path and the webhook
    /// receiver's granted branch use this; the plain [`Self::upsert`]
    /// forwards to it with `grantee_email = None` and stays the
    /// stable surface every test caller reads.
    ///
    /// The `grantee_email` column is what the standalone-mode
    /// MembershipView UNION reads to render "shared with you" rows
    /// in the switcher, since no `users.bunyip_user_id` is set in a
    /// deployment without Bunyip. Populating it is what makes the
    /// grant actually usable to the grantee in that mode.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_with_email(
        pool: &PgPool,
        bunyip_grant_id: Uuid,
        owner_bunyip_user_id: Uuid,
        grantee_bunyip_user_id: Uuid,
        mokosh_account_id: &str,
        role: Option<&str>,
        granted_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
        grantee_email: Option<&str>,
    ) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO mokosh_bunyip_grants (\
                 bunyip_grant_id, owner_bunyip_user_id, grantee_bunyip_user_id, \
                 mokosh_account_id, role, granted_at, revoked_at, grantee_email, \
                 updated_at\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) \
             ON CONFLICT (grantee_bunyip_user_id, mokosh_account_id) \
             DO UPDATE SET \
                 bunyip_grant_id = EXCLUDED.bunyip_grant_id, \
                 owner_bunyip_user_id = EXCLUDED.owner_bunyip_user_id, \
                 role = EXCLUDED.role, \
                 granted_at = EXCLUDED.granted_at, \
                 revoked_at = EXCLUDED.revoked_at, \
                 grantee_email = COALESCE(EXCLUDED.grantee_email, mokosh_bunyip_grants.grantee_email), \
                 updated_at = NOW()",
        )
        .bind(bunyip_grant_id)
        .bind(owner_bunyip_user_id)
        .bind(grantee_bunyip_user_id)
        .bind(mokosh_account_id)
        .bind(role)
        .bind(granted_at)
        .bind(revoked_at)
        .bind(grantee_email)
        .execute(pool)
        .await?;

        invalidate_cache(&GrantKey {
            grantee_bunyip_user_id,
            mokosh_account_id: mokosh_account_id.to_string(),
        });
        Ok(())
    }

    /// PMS-1208 finding 3 shim: pre-PMS-1208 8-arg surface, kept so
    /// every existing caller (the webhook receiver's revoked branch,
    /// the integration-test rig) compiles unchanged. Delegates to
    /// [`Self::upsert_with_email`] with `grantee_email = None`, which
    /// leaves the column untouched via COALESCE on ON CONFLICT and
    /// writes NULL on the INSERT branch.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        pool: &PgPool,
        bunyip_grant_id: Uuid,
        owner_bunyip_user_id: Uuid,
        grantee_bunyip_user_id: Uuid,
        mokosh_account_id: &str,
        role: Option<&str>,
        granted_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> AppResult<()> {
        Self::upsert_with_email(
            pool,
            bunyip_grant_id,
            owner_bunyip_user_id,
            grantee_bunyip_user_id,
            mokosh_account_id,
            role,
            granted_at,
            revoked_at,
            None,
        )
        .await
    }
}

fn read_cache(key: &GrantKey) -> Option<GrantSnapshot> {
    let guard = GRANT_CACHE.read().ok()?;
    guard.as_ref().and_then(|m| m.get(key)).cloned()
}

fn write_cache(key: GrantKey, snap: GrantSnapshot) {
    if let Ok(mut guard) = GRANT_CACHE.write() {
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(key, snap);
    }
}

fn invalidate_cache(key: &GrantKey) {
    if let Ok(mut guard) = GRANT_CACHE.write() {
        if let Some(map) = guard.as_mut() {
            map.remove(key);
        }
    }
}

/// Testing hook: drop every cached entry so a test's setup does not
/// see stale state from an earlier test in the same process. Callable
/// from the integration-test suite (`tests/mokosh_bunyip_grants.rs`),
/// which compiles against this crate's public API. A live process
/// should never need this - the webhook is the invalidation contract.
pub fn clear_cache_for_tests() {
    if let Ok(mut guard) = GRANT_CACHE.write() {
        *guard = None;
    }
}
