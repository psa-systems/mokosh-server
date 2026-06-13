//! SLA service.

use std::collections::HashSet;

use crate::modules::auth::TenantId;
use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::notifications::NotificationsService;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::clock::{self, BusinessSchedule, OperationalHours};
use super::models::*;

#[derive(Clone)]
pub struct SlaService {
    db: Database,
    /// When `Some`, the `sla_sweep` worker dispatches SLA at-risk /
    /// breach alerts through the notifications queue (templates from
    /// `notification_templates`, delivery driven by `DispatcherWorker`).
    /// When `None` (the `new` constructor, used by older test fixtures
    /// and the CRUD/evaluate paths that never sweep), no SLA alerts are
    /// dispatched. Mirrors the `AuthService::with_dispatcher` pattern.
    notifications: Option<NotificationsService>,
}

impl SlaService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            notifications: None,
        }
    }

    /// Like [`Self::new`] but wires the notifications dispatcher so the
    /// `sla_sweep` worker can enqueue at-risk / breach alerts. The
    /// server uses this constructor in `create_api_router` so the
    /// worker (spawned from `main.rs`) shares the same
    /// `NotificationsService` clone as the rest of the app.
    pub fn with_dispatcher(db: Database, notifications: NotificationsService) -> Self {
        Self {
            db,
            notifications: Some(notifications),
        }
    }

    /// Borrow the wired notifications dispatcher, if any. Used by the
    /// `sla_sweep` worker to fan out at-risk / breach alerts.
    pub(crate) fn notifications(&self) -> Option<&NotificationsService> {
        self.notifications.as_ref()
    }

    /// Connection pool accessor for the `sla_sweep` worker's ledger
    /// reads/writes.
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        self.db.pool()
    }

    /// Claim a `(ticket, kind)` ledger row for the `sla_sweep` worker
    /// under the ticket's tenant. Runs the `ON CONFLICT DO NOTHING`
    /// INSERT inside a tenant-scoped transaction (RLS `app.current_tenant`
    /// GUC set) so the ledger write is row-level isolated, then commits.
    /// Returns `rows_affected` (0 = already claimed by a prior tick or a
    /// racing replica). Lives here because the worker cannot reach the
    /// private `db` field directly.
    pub(crate) async fn claim_sla_notification(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        kind: &str,
    ) -> AppResult<u64> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let claimed = sqlx::query(
            r#"INSERT INTO sla_notifications (tenant_id, ticket_id, kind)
               VALUES ($1, $2, $3)
               ON CONFLICT (ticket_id, kind) DO NOTHING"#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(kind)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(claimed)
    }

    // PMS-108 policies --------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_policies(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<SlaPolicyResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sla_policies WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, PolicyRow>(
            r#"SELECT id, name, description, business_hours_id, is_default
               FROM sla_policies WHERE tenant_id = $1
               ORDER BY is_default DESC, name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_policy(
        &self,
        tenant_id: TenantId,
        request: &UpsertSlaPolicyRequest,
    ) -> AppResult<SlaPolicyResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query("UPDATE sla_policies SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO sla_policies (id, tenant_id, name, description, business_hours_id, is_default)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id).bind(tenant_id)
        .bind(&request.name).bind(&request.description).bind(request.business_hours_id).bind(request.is_default)
        .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(SlaPolicyResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            business_hours_id: request.business_hours_id,
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_policy(&self, tenant_id: TenantId, id: Uuid) -> AppResult<SlaPolicyResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, PolicyRow>(
            r#"SELECT id, name, description, business_hours_id, is_default
               FROM sla_policies WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("SlaPolicy".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_policy(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertSlaPolicyRequest,
    ) -> AppResult<SlaPolicyResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query(
                "UPDATE sla_policies SET is_default = FALSE WHERE tenant_id = $1 AND id <> $2",
            )
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        let n = sqlx::query(
            r#"UPDATE sla_policies SET name = $3, description = $4, business_hours_id = $5,
                   is_default = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.business_hours_id)
        .bind(request.is_default)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("SlaPolicy".to_string()));
        }
        tx.commit().await?;
        Ok(SlaPolicyResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            business_hours_id: request.business_hours_id,
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_policy(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM sla_policies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("SlaPolicy".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-109 targets ---------------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_targets(
        &self,
        tenant_id: TenantId,
        policy_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<SlaTargetResponse>, u64)> {
        // Tenant scoping via the policy join so a caller cannot list another tenant's targets.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM sla_targets t
               INNER JOIN sla_policies p ON t.sla_policy_id = p.id
               WHERE p.tenant_id = $1 AND p.id = $2"#,
        )
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, TargetRow>(
            r#"SELECT t.id, t.sla_policy_id, t.priority_id, t.first_response_hours,
                      t.resolution_hours, t.operational_hours
               FROM sla_targets t
               INNER JOIN sla_policies p ON t.sla_policy_id = p.id
               WHERE p.tenant_id = $1 AND p.id = $2
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(policy_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn upsert_target(
        &self,
        tenant_id: TenantId,
        policy_id: Uuid,
        request: &UpsertSlaTargetRequest,
    ) -> AppResult<SlaTargetResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sla_policies WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(policy_id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        drop(tx);
        if !exists {
            return Err(AppError::NotFound("SlaPolicy".to_string()));
        }
        let id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO sla_targets
               (sla_policy_id, priority_id, first_response_hours, resolution_hours, operational_hours)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (sla_policy_id, priority_id) DO UPDATE SET
                 first_response_hours = EXCLUDED.first_response_hours,
                 resolution_hours = EXCLUDED.resolution_hours,
                 operational_hours = EXCLUDED.operational_hours,
                 updated_at = NOW()
               RETURNING id"#,
        )
        .bind(policy_id).bind(request.priority_id)
        .bind(request.first_response_hours).bind(request.resolution_hours)
        .bind(&request.operational_hours)
        .fetch_one(self.db.pool()).await?;
        Ok(SlaTargetResponse {
            id,
            sla_policy_id: policy_id,
            priority_id: request.priority_id,
            first_response_hours: request.first_response_hours,
            resolution_hours: request.resolution_hours,
            operational_hours: request.operational_hours.clone(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_target(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"DELETE FROM sla_targets t USING sla_policies p
               WHERE t.sla_policy_id = p.id AND p.tenant_id = $1 AND t.id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("SlaTarget".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-110 business hours --------------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_business_hours(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<BusinessHoursResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM business_hours WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, BhRow>(
            r#"SELECT id, name, timezone, schedule, is_default
               FROM business_hours WHERE tenant_id = $1
               ORDER BY is_default DESC, name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_business_hours(
        &self,
        tenant_id: TenantId,
        request: &UpsertBusinessHoursRequest,
    ) -> AppResult<BusinessHoursResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query("UPDATE business_hours SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO business_hours (id, tenant_id, name, timezone, schedule, is_default)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.timezone)
        .bind(&request.schedule)
        .bind(request.is_default)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(BusinessHoursResponse {
            id,
            name: request.name.clone(),
            timezone: request.timezone.clone(),
            schedule: request.schedule.clone(),
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_business_hours(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertBusinessHoursRequest,
    ) -> AppResult<BusinessHoursResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // PMS-195: enforce a single default. Clear every other row's
        // `is_default` before promoting this one, mirroring
        // `create_business_hours`.
        if request.is_default {
            sqlx::query(
                "UPDATE business_hours SET is_default = FALSE WHERE tenant_id = $1 AND id <> $2",
            )
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        let n = sqlx::query(
            r#"UPDATE business_hours SET name = $3, timezone = $4, schedule = $5,
                   is_default = $6, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.timezone)
        .bind(&request.schedule)
        .bind(request.is_default)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("BusinessHours".to_string()));
        }
        tx.commit().await?;
        Ok(BusinessHoursResponse {
            id,
            name: request.name.clone(),
            timezone: request.timezone.clone(),
            schedule: request.schedule.clone(),
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_business_hours(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM business_hours WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("BusinessHours".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-111 holiday calendars -----------------------------------------------
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_holiday_calendars(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<HolidayCalendarResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM holiday_calendars WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, HolidayRow>(
            r#"SELECT id, name, holidays FROM holiday_calendars
               WHERE tenant_id = $1
               ORDER BY name
               LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_holiday_calendar(
        &self,
        tenant_id: TenantId,
        request: &UpsertHolidayCalendarRequest,
    ) -> AppResult<HolidayCalendarResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO holiday_calendars (id, tenant_id, name, holidays)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.holidays)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(HolidayCalendarResponse {
            id,
            name: request.name.clone(),
            holidays: request.holidays.clone(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_holiday_calendar(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertHolidayCalendarRequest,
    ) -> AppResult<HolidayCalendarResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query(
            r#"UPDATE holiday_calendars SET name = $3, holidays = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.holidays)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("HolidayCalendar".to_string()));
        }
        tx.commit().await?;
        Ok(HolidayCalendarResponse {
            id,
            name: request.name.clone(),
            holidays: request.holidays.clone(),
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_holiday_calendar(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let n = sqlx::query("DELETE FROM holiday_calendars WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n == 0 {
            return Err(AppError::NotFound("HolidayCalendar".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // PMS-112 / PMS-106 evaluator ---------------------------------------------
    /// Compute and persist `tickets.first_response_due`, `resolution_due`,
    /// `sla_due_date` for the ticket based on its priority's targets in
    /// its assigned SLA policy.
    ///
    /// The applicable policy is the ticket's `sla_id` when set, else the
    /// tenant's default policy (`is_default = TRUE`). The policy's
    /// `business_hours` row supplies the timezone + weekly schedule, and
    /// the business-hours row's `holidays` (a `UUID[]` of
    /// `holiday_calendars`) supply the non-working dates. Each target is
    /// then evaluated through [`clock::due_at`] using the target's own
    /// `operational_hours` (`24x7` -> wall-clock, `business_hours` ->
    /// business-hours-aware, PMS-106). If the policy has no business
    /// hours configured every target degrades to 24x7.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn evaluate_for_ticket(&self, tenant_id: TenantId, ticket_id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(Option<Uuid>, Uuid, DateTime<Utc>)> = sqlx::query_as(
            r#"SELECT sla_id, priority_id, created_at FROM tickets
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((sla_id, priority_id, created_at)) = row else {
            return Ok(());
        };

        // Resolve the applicable policy and its business-hours id in one
        // query so we do not round-trip twice.
        let policy: Option<(Uuid, Option<Uuid>)> = match sla_id {
            Some(p) => sqlx::query_as(
                "SELECT id, business_hours_id FROM sla_policies WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(p)
            .fetch_optional(&mut *tx)
            .await?,
            None => {
                sqlx::query_as(
                    r#"SELECT id, business_hours_id FROM sla_policies
                   WHERE tenant_id = $1 AND is_default = TRUE LIMIT 1"#,
                )
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?
            }
        };
        drop(tx);
        let Some((policy_id, business_hours_id)) = policy else {
            return Ok(()); // no policy configured; nothing to evaluate
        };

        let target: Option<(Option<Decimal>, Option<Decimal>, Option<String>)> = sqlx::query_as(
            r#"SELECT first_response_hours, resolution_hours, operational_hours
               FROM sla_targets
               WHERE sla_policy_id = $1 AND priority_id = $2"#,
        )
        .bind(policy_id)
        .bind(priority_id)
        .fetch_optional(self.db.pool())
        .await?;
        let Some((fr, res, op_hours)) = target else {
            return Ok(());
        };

        // Load the policy's business hours (timezone + weekly schedule)
        // and the holiday dates referenced by that row. Absent business
        // hours => an all-closed schedule, which `clock::due_at` degrades
        // to 24x7.
        let (schedule, holidays) = self
            .load_schedule_and_holidays(tenant_id, business_hours_id)
            .await?;
        let operational =
            OperationalHours::from_db(op_hours.as_deref().unwrap_or("business_hours"));

        let fr_due = decimal_to_hours(fr)
            .map(|h| clock::due_at(created_at, h, &schedule, &holidays, operational));
        let res_due = decimal_to_hours(res)
            .map(|h| clock::due_at(created_at, h, &schedule, &holidays, operational));

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"UPDATE tickets SET first_response_due = $3, resolution_due = $4,
                   sla_due_date = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(fr_due)
        .bind(res_due)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Load and parse the [`BusinessSchedule`] for `business_hours_id`
    /// plus the holiday dates referenced by that row's `holidays`
    /// (`UUID[]` of `holiday_calendars`). A missing id or row yields an
    /// empty (all-closed) schedule and an empty holiday set, which the
    /// clock degrades to 24x7.
    async fn load_schedule_and_holidays(
        &self,
        tenant_id: TenantId,
        business_hours_id: Option<Uuid>,
    ) -> AppResult<(BusinessSchedule, HashSet<NaiveDate>)> {
        // No business hours on the policy: an empty (all-closed) schedule
        // that `clock::due_at` degrades to 24x7, plus no holidays.
        let empty = || {
            (
                BusinessSchedule::parse("UTC", &serde_json::json!({})),
                HashSet::new(),
            )
        };

        let Some(bh_id) = business_hours_id else {
            return Ok(empty());
        };

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let bh: Option<(String, serde_json::Value, Option<Vec<Uuid>>)> = sqlx::query_as(
            r#"SELECT timezone, schedule, holidays FROM business_hours
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(bh_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((timezone, schedule_json, holiday_calendar_ids)) = bh else {
            return Ok(empty());
        };

        let schedule = BusinessSchedule::parse(&timezone, &schedule_json);

        let mut holidays: HashSet<NaiveDate> = HashSet::new();
        if let Some(ids) = holiday_calendar_ids {
            if !ids.is_empty() {
                let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
                    r#"SELECT holidays FROM holiday_calendars
                       WHERE tenant_id = $1 AND id = ANY($2)"#,
                )
                .bind(tenant_id)
                .bind(&ids)
                .fetch_all(&mut *tx)
                .await?;
                for (json,) in rows {
                    holidays.extend(clock::parse_holidays(&json));
                }
            }
        }

        Ok((schedule, holidays))
    }
}

/// Convert a `DECIMAL` hours value (e.g. `1.50`) into `f64` hours for the
/// clock. Returns `None` for NULL or unparseable values.
fn decimal_to_hours(d: Option<Decimal>) -> Option<f64> {
    d.and_then(|h| h.to_string().parse::<f64>().ok())
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    business_hours_id: Option<Uuid>,
    is_default: Option<bool>,
}

impl From<PolicyRow> for SlaPolicyResponse {
    fn from(r: PolicyRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            business_hours_id: r.business_hours_id,
            is_default: r.is_default.unwrap_or(false),
        }
    }
}

#[derive(sqlx::FromRow)]
struct TargetRow {
    id: Uuid,
    sla_policy_id: Uuid,
    priority_id: Uuid,
    first_response_hours: Option<Decimal>,
    resolution_hours: Option<Decimal>,
    operational_hours: Option<String>,
}

impl From<TargetRow> for SlaTargetResponse {
    fn from(r: TargetRow) -> Self {
        Self {
            id: r.id,
            sla_policy_id: r.sla_policy_id,
            priority_id: r.priority_id,
            first_response_hours: r.first_response_hours,
            resolution_hours: r.resolution_hours,
            operational_hours: r
                .operational_hours
                .unwrap_or_else(|| "business_hours".into()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct BhRow {
    id: Uuid,
    name: String,
    timezone: String,
    schedule: serde_json::Value,
    is_default: Option<bool>,
}

impl From<BhRow> for BusinessHoursResponse {
    fn from(r: BhRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            timezone: r.timezone,
            schedule: r.schedule,
            is_default: r.is_default.unwrap_or(false),
        }
    }
}

#[derive(sqlx::FromRow)]
struct HolidayRow {
    id: Uuid,
    name: String,
    holidays: serde_json::Value,
}

impl From<HolidayRow> for HolidayCalendarResponse {
    fn from(r: HolidayRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            holidays: r.holidays,
        }
    }
}
