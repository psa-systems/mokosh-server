//! Store and read paths for monitored systems and status observations.

use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::models::{
    CompanyBackupStatusResponse, CompanySystemBackup, CurrentObservation, IngestStatusRequest,
    SystemStatusResponse, CHECK_KINDS, OUTCOMES,
};
use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

/// Outcome of an ingest call. The caller reports the shape back on the
/// wire so a replaying poller can see when its retry landed a fresh row
/// and when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// A new row was inserted and, on first sight, a `monitored_systems`
    /// row was created alongside it.
    Recorded,
    /// The same (system, check_kind, observed_at) triple was already on
    /// disk. Nothing changed.
    Duplicate,
}

/// System status service handle.
#[derive(Clone)]
pub struct StatusService {
    db: Database,
}

impl StatusService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Refuse an unknown check kind or outcome up front so the CHECK
    /// constraint is a backstop rather than a first defence. The 422 the
    /// SPA renders inline is friendlier than the raw constraint error.
    fn validate_vocab(request: &IngestStatusRequest) -> AppResult<()> {
        if !CHECK_KINDS.contains(&request.check_kind.as_str()) {
            return Err(AppError::validation_field(
                "check_kind",
                format!(
                    "unknown check_kind `{}`; accepted: {}",
                    request.check_kind,
                    CHECK_KINDS.join(", ")
                ),
            ));
        }
        if !OUTCOMES.contains(&request.outcome.as_str()) {
            return Err(AppError::validation_field(
                "outcome",
                format!(
                    "unknown outcome `{}`; accepted: {}",
                    request.outcome,
                    OUTCOMES.join(", ")
                ),
            ));
        }
        Ok(())
    }

    /// Ingest one observation. Idempotent per (system, check_kind,
    /// observed_at): a replay adds no row, and the return value tells
    /// the caller which happened.
    ///
    /// Resolves the company from the RMM device mapping. An unmapped
    /// device is refused with 422 so an operator can see it: silently
    /// writing observations for a system nobody has claimed yet is how a
    /// tenant ends up billing a company that does not own the box.
    pub async fn ingest(
        &self,
        tenant_id: TenantId,
        external_source: &str,
        request: &IngestStatusRequest,
    ) -> AppResult<IngestOutcome> {
        Self::validate_vocab(request)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let company_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT company_id FROM rmm_device_mappings \
             WHERE tenant_id = $1 AND rmm_connection_id = $2 AND rmm_device_id = $3 \
             LIMIT 1",
        )
        .bind(*tenant_id)
        .bind(request.rmm_connection_id)
        .bind(&request.rmm_device_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(company_id) = company_id else {
            return Err(AppError::validation_field(
                "rmm_device_id",
                format!(
                    "no company is mapped to rmm_device_id `{}` on this connection; \
                     map it under Settings → RMM before it can be tracked",
                    request.rmm_device_id
                ),
            ));
        };

        let system_id: Uuid = sqlx::query_scalar(
            "INSERT INTO monitored_systems ( \
                 tenant_id, company_id, external_source, external_id, name, \
                 first_seen_at, last_seen_at \
             ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) \
             ON CONFLICT (tenant_id, external_source, external_id) \
             DO UPDATE SET \
                 last_seen_at = NOW(), \
                 company_id = EXCLUDED.company_id, \
                 name = CASE \
                     WHEN monitored_systems.deleted_at IS NULL THEN monitored_systems.name \
                     ELSE EXCLUDED.name \
                 END, \
                 deleted_at = NULL, \
                 updated_at = NOW() \
             RETURNING id",
        )
        .bind(*tenant_id)
        .bind(company_id)
        .bind(external_source)
        .bind(&request.rmm_device_id)
        .bind(&request.system_name)
        .fetch_one(&mut *tx)
        .await?;

        let result = sqlx::query(
            "INSERT INTO status_observations ( \
                 tenant_id, company_id, monitored_system_id, \
                 check_kind, outcome, observed_at, payload \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (monitored_system_id, check_kind, observed_at) DO NOTHING",
        )
        .bind(*tenant_id)
        .bind(company_id)
        .bind(system_id)
        .bind(&request.check_kind)
        .bind(&request.outcome)
        .bind(request.observed_at)
        .bind(&request.payload)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(if result.rows_affected() == 0 {
            IngestOutcome::Duplicate
        } else {
            IngestOutcome::Recorded
        })
    }

    /// The system row plus, per known check kind, the most recent
    /// observation. Missing kinds do not appear in the list; a caller
    /// that expects one and finds none knows nothing has ever been seen
    /// for that kind on this system.
    pub async fn latest_for_system(
        &self,
        tenant_id: TenantId,
        system_id: Uuid,
    ) -> AppResult<SystemStatusResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, company_id, external_source, external_id, \
                    name, first_seen_at, last_seen_at \
             FROM monitored_systems \
             WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        )
        .bind(system_id)
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Monitored system".to_string()))?;

        // DISTINCT ON keyed by check_kind, ordered by observed_at DESC,
        // is the "current status per kind" idiom in Postgres and matches
        // the index laid down in the migration.
        let observations: Vec<CurrentObservation> = sqlx::query(
            "SELECT DISTINCT ON (check_kind) \
                    check_kind, outcome, observed_at, payload \
             FROM status_observations \
             WHERE monitored_system_id = $1 \
             ORDER BY check_kind, observed_at DESC",
        )
        .bind(system_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|r| CurrentObservation {
            check_kind: r.get("check_kind"),
            outcome: r.get("outcome"),
            observed_at: r.get::<DateTime<Utc>, _>("observed_at"),
            payload: r.get("payload"),
        })
        .collect();

        Ok(SystemStatusResponse {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            company_id: row.get("company_id"),
            external_source: row.get("external_source"),
            external_id: row.get("external_id"),
            name: row.get("name"),
            first_seen_at: row.get::<DateTime<Utc>, _>("first_seen_at"),
            last_seen_at: row.get::<DateTime<Utc>, _>("last_seen_at"),
            observations,
        })
    }

    /// Fraction of backup observations in the given period whose outcome
    /// was `success`. `1.0` on no observations at all, so the SPA renders
    /// "nothing to grade" rather than "everything failed"; the numerator
    /// and denominator are returned alongside the rate so the caller can
    /// distinguish the two.
    pub async fn backup_success_rate(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> AppResult<super::models::BackupSuccessRateResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query(
            "SELECT \
                 COUNT(*) FILTER (WHERE outcome = 'success')::BIGINT AS success, \
                 COUNT(*)::BIGINT AS total \
             FROM status_observations \
             WHERE tenant_id = $1 AND company_id = $2 AND check_kind = 'backup' \
               AND observed_at >= $3 AND observed_at < $4",
        )
        .bind(*tenant_id)
        .bind(company_id)
        .bind(from)
        .bind(to)
        .fetch_one(&mut *tx)
        .await?;

        let success: i64 = row.get("success");
        let total: i64 = row.get("total");
        let rate = if total == 0 {
            1.0
        } else {
            success as f64 / total as f64
        };
        Ok(super::models::BackupSuccessRateResponse {
            company_id,
            from,
            to,
            success: success as u64,
            total: total as u64,
            rate,
        })
    }

    /// Uptime approximation over the given period, across every check
    /// kind for every system the company owns.
    ///
    /// A first-cut definition: the fraction of observations in the window
    /// whose outcome was NOT `failure` (that is, `success` or `warning`).
    /// True time-in-state uptime needs interval math over paired up/down
    /// transitions and is out of scope for the first pass; the reports
    /// surface documents which of the two this is. `1.0` on no
    /// observations so a company with no monitored systems does not read
    /// as "totally down".
    pub async fn uptime(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> AppResult<super::models::UptimeResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query(
            "SELECT \
                 COUNT(*) FILTER (WHERE outcome IN ('success', 'warning'))::BIGINT AS up, \
                 COUNT(*)::BIGINT AS total \
             FROM status_observations \
             WHERE tenant_id = $1 AND company_id = $2 \
               AND observed_at >= $3 AND observed_at < $4",
        )
        .bind(*tenant_id)
        .bind(company_id)
        .bind(from)
        .bind(to)
        .fetch_one(&mut *tx)
        .await?;

        let up: i64 = row.get("up");
        let total: i64 = row.get("total");
        let rate = if total == 0 {
            1.0
        } else {
            up as f64 / total as f64
        };
        Ok(super::models::UptimeResponse {
            company_id,
            from,
            to,
            up_observations: up as u64,
            total_observations: total as u64,
            rate,
        })
    }

    /// Delete every observation older than the cutoff. Cross-tenant
    /// maintenance: there is no `CurrentUser` and no tenant GUC to set,
    /// so the delete runs on the migrator pool. Bounded by `observed_at`,
    /// which the primary index covers, and returns the count so the
    /// worker can log a size per tick.
    pub async fn purge_older_than(&self, cutoff: DateTime<Utc>) -> AppResult<u64> {
        // SAFETY (PMS-285): cross-tenant maintenance. The delete is
        // bounded by `observed_at` and the caller is a background job,
        // never a request handler.
        let result = sqlx::query("DELETE FROM status_observations WHERE observed_at < $1")
            .bind(cutoff)
            .execute(self.db.migrator_pool())
            .await?;
        Ok(result.rows_affected())
    }

    /// Per-company rollup of the CURRENT backup outcome for every system
    /// owned by that company. A system that has never carried a backup
    /// observation still appears, with `latest = None`, so the caller
    /// can render "unseen" separately from "failing".
    pub async fn backup_for_company(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
    ) -> AppResult<CompanyBackupStatusResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let rows = sqlx::query(
            "SELECT ms.id AS system_id, ms.name AS system_name, \
                    so.check_kind, so.outcome, so.observed_at, so.payload \
             FROM monitored_systems ms \
             LEFT JOIN LATERAL ( \
                 SELECT check_kind, outcome, observed_at, payload \
                 FROM status_observations \
                 WHERE monitored_system_id = ms.id AND check_kind = 'backup' \
                 ORDER BY observed_at DESC \
                 LIMIT 1 \
             ) so ON TRUE \
             WHERE ms.tenant_id = $1 AND ms.company_id = $2 AND ms.deleted_at IS NULL \
             ORDER BY ms.name",
        )
        .bind(*tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;

        let systems = rows
            .into_iter()
            .map(|r| {
                let outcome: Option<String> = r.try_get("outcome").ok();
                let latest = outcome.map(|out| CurrentObservation {
                    check_kind: "backup".to_string(),
                    outcome: out,
                    observed_at: r
                        .get::<Option<DateTime<Utc>>, _>("observed_at")
                        .unwrap_or_else(Utc::now),
                    payload: r
                        .get::<Option<serde_json::Value>, _>("payload")
                        .unwrap_or_else(|| serde_json::json!({})),
                });
                CompanySystemBackup {
                    monitored_system_id: r.get("system_id"),
                    system_name: r.get("system_name"),
                    latest,
                }
            })
            .collect();

        Ok(CompanyBackupStatusResponse {
            company_id,
            systems,
        })
    }
}
