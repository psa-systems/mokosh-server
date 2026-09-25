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
/// `read_only` maps to [`UserRole::Technician`], the least-privilege
/// mokosh role that already exists. This is deliberately over-
/// privileged for now: mokosh has no first-class read-only tier, and
/// a real one is a follow-up (a ticket separately opened once the
/// grant surface has enough traffic to justify the schema move).
/// Until then a `read_only` grantee has technician-level WRITE
/// access on the granted tenant; a grant issuer who needs strict
/// read-only should not issue this role yet.
pub fn map_grant_role(vocab: &str) -> Option<UserRole> {
    match vocab {
        "admin" => Some(UserRole::Admin),
        "manager" => Some(UserRole::Manager),
        "technician" => Some(UserRole::Technician),
        "finance" => Some(UserRole::Finance),
        // See the note above: intentionally maps to Technician until
        // a first-class read-only tier lands.
        "read_only" => Some(UserRole::Technician),
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
    /// `granted_at` is the event's `at`. It is stored as `event_at` and an
    /// event only applies when it is strictly newer than the stored one, so
    /// a late, duplicate or replayed event changes nothing (PMS-1295).
    /// Returns `true` when a row was inserted or changed; only then is the
    /// cache entry for the (grantee, account) pair invalidated.
    ///
    /// PMS-1210: on a revoked event the receiver stamps `revoked_by =
    /// 'owner'` so the audit line can tell an owner-side revoke apart
    /// from a grantee's "Leave account" gesture. A granted event clears
    /// the initiator back to `NULL`, so a re-grant does not carry the
    /// stale initiator of a previous revoke.
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
    ) -> AppResult<bool> {
        let revoked_by: Option<&str> = revoked_at.is_some().then_some("owner");
        let result = sqlx::query(
            "INSERT INTO mokosh_bunyip_grants (\
                 bunyip_grant_id, owner_bunyip_user_id, grantee_bunyip_user_id, \
                 mokosh_account_id, role, granted_at, revoked_at, revoked_by, event_at, updated_at\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $6, NOW()) \
             ON CONFLICT (grantee_bunyip_user_id, mokosh_account_id) \
             DO UPDATE SET \
                 bunyip_grant_id = EXCLUDED.bunyip_grant_id, \
                 owner_bunyip_user_id = EXCLUDED.owner_bunyip_user_id, \
                 role = EXCLUDED.role, \
                 granted_at = EXCLUDED.granted_at, \
                 revoked_at = EXCLUDED.revoked_at, \
                 revoked_by = EXCLUDED.revoked_by, \
                 event_at = EXCLUDED.event_at, \
                 updated_at = NOW() \
             WHERE mokosh_bunyip_grants.event_at < EXCLUDED.event_at",
        )
        .bind(bunyip_grant_id)
        .bind(owner_bunyip_user_id)
        .bind(grantee_bunyip_user_id)
        .bind(mokosh_account_id)
        .bind(role)
        .bind(granted_at)
        .bind(revoked_at)
        .bind(revoked_by)
        .execute(pool)
        .await?;

        let changed = result.rows_affected() > 0;
        if changed {
            invalidate_cache(&GrantKey {
                grantee_bunyip_user_id,
                mokosh_account_id: mokosh_account_id.to_string(),
            });
        }
        Ok(changed)
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

/// Outcome of [`MokoshBunyipGrantService::grantee_leave`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GranteeLeaveOutcome {
    /// The row was found and this call is what revoked it. The receiver
    /// tombstoned the granted-tenant `users` placement in the same
    /// transaction.
    Revoked,
    /// The row was found and was already revoked; the caller's replay is
    /// a no-op. Answered with `204` at the route to match the enumeration
    /// resistant shape the owner-side revoke uses.
    AlreadyRevoked,
    /// No row matches the caller and id pair. Answered with `404` at the
    /// route so a foreign id is indistinguishable from a nonexistent one,
    /// matching the owner-side revoke.
    NotFound,
}

impl MokoshBunyipGrantService {
    /// PMS-1210: the caller leaves an account they were granted access to.
    ///
    /// Identifies the row by the mokosh-side `id` AND the caller's
    /// `bunyip_user_id` in one predicate, so a foreign id is
    /// enumeration-resistant: the query answers `NotFound` for both a
    /// nonexistent id and one that belongs to a different grantee, which
    /// mirrors the owner-side revoke's 404 posture.
    ///
    /// The write and the belt-and-braces tombstone on the granted-tenant
    /// `users` row live in one transaction so a caller cannot end up half
    /// revoked. The tombstone shape (`deleted_at = COALESCE(...)`) matches
    /// the receiver's `mokosh_grant_changed` webhook path, so a grantee
    /// leaving and the owner revoking converge on the same on-disk state.
    ///
    /// The 30s snapshot cache is invalidated on a successful revoke so the
    /// next request from anyone in this process sees the change without
    /// waiting for the TTL, the shape `upsert` already uses.
    pub async fn grantee_leave(
        pool: &PgPool,
        row_id: Uuid,
        grantee_bunyip_user_id: Uuid,
    ) -> AppResult<GranteeLeaveOutcome> {
        let mut tx = pool.begin().await?;

        let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT mokosh_account_id, revoked_at FROM mokosh_bunyip_grants \
             WHERE id = $1 AND grantee_bunyip_user_id = $2 FOR UPDATE",
        )
        .bind(row_id)
        .bind(grantee_bunyip_user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((mokosh_account_id, revoked_at)) = row else {
            return Ok(GranteeLeaveOutcome::NotFound);
        };

        if revoked_at.is_some() {
            return Ok(GranteeLeaveOutcome::AlreadyRevoked);
        }

        sqlx::query(
            "UPDATE mokosh_bunyip_grants \
             SET revoked_at = NOW(), role = NULL, revoked_by = 'grantee', \
                 event_at = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(row_id)
        .execute(&mut *tx)
        .await?;

        // Belt-and-braces: tombstone the placement row so the grantee's
        // next request cannot serve any tenant-scoped read out of stale
        // rows the JIT provisioner minted. The webhook path does the same.
        sqlx::query(
            "UPDATE users \
             SET deleted_at = COALESCE(deleted_at, NOW()) \
             WHERE bunyip_user_id = $1 \
               AND tenant_id = (SELECT id FROM tenants WHERE slug = $2)",
        )
        .bind(grantee_bunyip_user_id)
        .bind(&mokosh_account_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        invalidate_cache(&GrantKey {
            grantee_bunyip_user_id,
            mokosh_account_id,
        });

        Ok(GranteeLeaveOutcome::Revoked)
    }
}
