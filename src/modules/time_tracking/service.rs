//! Time-tracking service. Endpoints land incrementally across PMS-42.

use chrono::{Datelike, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;
use mokosh_types::tickets::BillingStatus;

#[derive(Clone)]
pub struct TimeTrackingService {
    db: Database,
}

impl TimeTrackingService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // PMS-50 work types
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_work_types(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<WorkTypeResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM work_types WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;

        let rows = sqlx::query_as::<_, WorkTypeRow>(
            r#"
            SELECT id, name, description, default_billable, default_rate,
                   is_active, sort_order
            FROM work_types
            WHERE tenant_id = $1
            ORDER BY sort_order, name
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_work_type(
        &self,
        tenant_id: TenantId,
        request: &UpsertWorkTypeRequest,
        ctx: &AuditCtx,
    ) -> AppResult<WorkTypeResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO work_types
                (tenant_id, name, description, default_billable, default_rate,
                 is_active, sort_order)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.default_billable)
        .bind(request.default_rate)
        .bind(request.is_active)
        .bind(request.sort_order)
        .fetch_one(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM work_types t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "work_types",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(WorkTypeResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            default_billable: request.default_billable,
            default_rate: request.default_rate,
            is_active: request.is_active,
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_work_type(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertWorkTypeRequest,
    ) -> AppResult<WorkTypeResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let affected = sqlx::query(
            r#"
            UPDATE work_types SET
                name = $3, description = $4, default_billable = $5,
                default_rate = $6, is_active = $7, sort_order = $8,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.default_billable)
        .bind(request.default_rate)
        .bind(request.is_active)
        .bind(request.sort_order)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Work type".to_string()));
        }
        tx.commit().await?;
        Ok(WorkTypeResponse {
            id,
            name: request.name.clone(),
            description: request.description.clone(),
            default_billable: request.default_billable,
            default_rate: request.default_rate,
            is_active: request.is_active,
            sort_order: request.sort_order,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_work_type(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let affected = sqlx::query("DELETE FROM work_types WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Work type".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-44 / PMS-45 time entries
    // ========================================================================

    /// Compute the worked minutes for an entry. Precedence (PMS-395):
    /// explicit `worked_minutes` > `duration_minutes` > derived from
    /// (start, end). This is the actual time spent and is never rounded.
    fn compute_minutes(request: &CreateTimeEntryRequest) -> AppResult<i32> {
        if let Some(m) = request.worked_minutes {
            return Ok(m);
        }
        if let Some(m) = request.duration_minutes {
            return Ok(m);
        }
        if let (Some(s), Some(e)) = (request.start_time, request.end_time) {
            let secs = (e - s).num_minutes();
            if secs < 0 {
                return Err(AppError::BadRequest(
                    "end_time must be after start_time".to_string(),
                ));
            }
            return Ok(secs as i32);
        }
        Err(AppError::BadRequest(
            "Either duration_minutes or (start_time, end_time) must be supplied".to_string(),
        ))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_time_entries(
        &self,
        tenant_id: TenantId,
        filter: &TimeEntryFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TimeEntryResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        // PMS-145: the data and count queries bind a different number of
        // leading params (data: $1 tenant, $2 limit, $3 offset -> filters
        // from $4; count: $1 tenant -> filters from $2), so each needs its
        // OWN placeholder numbering. Sharing one where_clause made the count
        // query reference an unbound $4 and 500 on any filter. Mirrors
        // billing::list_invoices.
        // The data query joins tickets/projects/tasks (which also carry
        // tenant_id), so its predicates must be qualified with the `te` alias
        // to avoid ambiguous-column errors. The count query has no join, so it
        // stays on bare time_entries columns.
        let mut data_conds = vec!["te.tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;
        let mut push_filter = |col: &str, op: &str| {
            data_conds.push(format!("te.{col} {op} ${data_idx}"));
            count_conds.push(format!("{col} {op} ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        };
        if filter.user_id.is_some() {
            push_filter("user_id", "=");
        }
        if filter.ticket_id.is_some() {
            push_filter("ticket_id", "=");
        }
        if filter.project_id.is_some() {
            push_filter("project_id", "=");
        }
        if filter.date_from.is_some() {
            push_filter("date", ">=");
        }
        if filter.date_to.is_some() {
            push_filter("date", "<=");
        }
        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        // order_by appends the sort direction to a single column name, so
        // default_field must be a bare column - embedding "DESC" here yielded
        // "ORDER BY date DESC, start_time DESC DESC" and 500'd every list call
        // (PMS-145). Default direction is already DESC (newest first).
        // Every allowed sort field lives on time_entries; qualify it with the
        // `te` alias so a `created_at` sort is not ambiguous against the joined
        // tables (each of which also has a created_at).
        let order_by = pagination.order_by("date", mokosh_types::sort::TIME_ENTRIES)?;
        let order_by = format!("te.{order_by}");
        let query = format!(
            r#"
            SELECT te.id, te.user_id, te.date, te.start_time, te.end_time, te.duration_minutes,
                   te.worked_minutes, te.billable_minutes,
                   te.work_type_id, te.ticket_id, te.project_id, te.task_id, te.company_id, te.entry_kind, te.notes,
                   te.is_billable, te.billing_status, te.hourly_rate, te.total_amount,
                   te.approval_status, te.work_category, te.created_at, te.updated_at,
                   tk.ticket_number, tk.title AS ticket_title,
                   pr.name AS project_name, ta.title AS task_title
            FROM time_entries te
            LEFT JOIN tickets  tk ON tk.id = te.ticket_id
            LEFT JOIN projects pr ON pr.id = te.project_id
            LEFT JOIN tasks    ta ON ta.id = te.task_id
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM time_entries WHERE {count_where}");
        let mut q = sqlx::query_as::<_, TimeEntryRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(v) = filter.user_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.ticket_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.project_id {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.date_from {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        if let Some(v) = filter.date_to {
            q = q.bind(v);
            cq = cq.bind(v);
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q.fetch_all(&mut *tx).await?;
        let total = cq.fetch_one(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_time_entry(
        &self,
        tenant_id: TenantId,
        request: &CreateTimeEntryRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TimeEntryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Write-side tenant validation: FKs check existence, not ownership,
        // so a request body could otherwise attach time to another tenant's
        // work type / ticket / company.
        let defaults = fetch_work_type_defaults(&mut *tx, tenant_id, request.work_type_id).await?;
        if let Some(company_id) = request.company_id {
            assert_company_in_tenant(&mut *tx, tenant_id, company_id).await?;
        }
        if let Some(ticket_id) = request.ticket_id {
            assert_ticket_in_tenant(&mut *tx, tenant_id, ticket_id).await?;
        }
        // PMS-942: whose time this is, settled before anything is priced. It
        // decides whether the entry can be billed at all, so resolving it after
        // `resolve_billing` would mean pricing employee time and then throwing
        // the figure away.
        let kind = resolve_entry_kind(EntryKindInput {
            requested: request.entry_kind.as_deref(),
            company_id: request.company_id,
            own_company_id: own_company_id(&mut *tx, tenant_id).await?,
            ticket_id: request.ticket_id,
            project_id: request.project_id,
            task_id: request.task_id,
            contract_id: None,
            is_billable: request.is_billable,
        })?;
        let work_category = derive_work_category(
            request.work_category.as_deref(),
            request.ticket_id,
            request.project_id,
        )?;

        // PMS-395: worked time is the unrounded actual time and is stored
        // as-is. Rounding now derives only the billable figure (unless the
        // caller supplies one explicitly), so the worked figure is never
        // mutated to fit the billing increment.
        let worked = Self::compute_minutes(request)?;
        let rounding = default_rounding_rule(&mut *tx, tenant_id).await?;
        // PMS-942: employee time bills nobody, so an explicit billable figure on
        // it is discarded rather than stored and then filtered out downstream.
        let billable = if kind.billable {
            match request.billable_minutes {
                Some(b) => b,
                None => derive_billable_minutes(worked, true, rounding.as_ref()),
            }
        } else {
            0
        };
        // PMS-396: reject when this entry would push the user's worked total
        // for the date over the tenant's per-day cap. The SUM runs inside `tx`
        // so it is consistent with the INSERT below.
        let cap_minutes =
            crate::modules::settings::read_max_minutes_per_day(&self.db, tenant_id).await?;
        let existing =
            day_minutes_excluding(&mut *tx, tenant_id, request.user_id, request.date, None).await?;
        enforce_day_cap(existing, worked, cap_minutes)?;
        // total_amount is priced on billable minutes, not worked minutes.
        let (hourly_rate, total) =
            resolve_billing(request.hourly_rate, kind.billable, &defaults, billable);
        // PMS-951: which contract this time draws against, derived rather than
        // asked for. The contract covering a piece of work follows from the
        // company, and putting a picker in front of the person logging time
        // invites picking the wrong one.
        let contract_id = block_hours_contract_for(
            &mut *tx,
            tenant_id,
            request.company_id,
            request.date,
            kind.kind,
            kind.billable,
        )
        .await?;
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO time_entries (
                id, tenant_id, user_id, date, start_time, end_time,
                duration_minutes, worked_minutes, billable_minutes,
                work_type_id, ticket_id, project_id,
                company_id, notes, is_billable, hourly_rate, total_amount, task_id,
                work_category, entry_kind, billing_status, contract_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.user_id)
        .bind(request.date)
        .bind(request.start_time)
        .bind(request.end_time)
        .bind(worked)
        .bind(worked)
        .bind(billable)
        .bind(request.work_type_id)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(request.company_id)
        .bind(&request.notes)
        .bind(kind.billable)
        .bind(hourly_rate)
        .bind(total)
        .bind(request.task_id)
        .bind(&work_category)
        .bind(kind.kind)
        // PMS-944: invoiceable on the strength of having been logged. Before
        // this the column took its `not_billed` DEFAULT and only weekly
        // timesheet approval ever moved it, so nothing logged on a tenant with
        // timesheets off could reach an invoice at all.
        .bind(resolve_billing_status(kind.billable, None))
        .bind(contract_id)
        .execute(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM time_entries t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "time_entries",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        // PMS-951: the hours come off the contract because the work was logged,
        // which is where PMS-944 put every other consequence of logging it.
        // Approval cannot be the consumption point any more: it is gated behind
        // the timesheets module (PMS-943), so a tenant with timesheets off would
        // never draw a single hour.
        //
        // After the commit, like the approval path it replaces, because
        // `consume_hours` manages its own transaction. A failure between the two
        // leaves the entry unconsumed rather than consumed twice, which is the
        // recoverable direction: an operator can see hours that have not been
        // drawn, where a double draw is a client's allotment silently short.
        self.consume_for_entry(tenant_id, id).await?;
        self.get_time_entry(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_time_entry(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> AppResult<TimeEntryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, TimeEntryRow>(
            r#"
            SELECT te.id, te.user_id, te.date, te.start_time, te.end_time, te.duration_minutes,
                   te.worked_minutes, te.billable_minutes,
                   te.work_type_id, te.ticket_id, te.project_id, te.task_id, te.company_id, te.entry_kind, te.notes,
                   te.is_billable, te.billing_status, te.hourly_rate, te.total_amount,
                   te.approval_status, te.work_category, te.created_at, te.updated_at,
                   tk.ticket_number, tk.title AS ticket_title,
                   pr.name AS project_name, ta.title AS task_title
            FROM time_entries te
            LEFT JOIN tickets  tk ON tk.id = te.ticket_id
            LEFT JOIN projects pr ON pr.id = te.project_id
            LEFT JOIN tasks    ta ON ta.id = te.task_id
            WHERE te.tenant_id = $1 AND te.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Time entry".to_string()))?;
        Ok(row.into())
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_time_entry(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateTimeEntryRequest,
    ) -> AppResult<TimeEntryResponse> {
        let current = self.get_time_entry(tenant_id, id).await?;
        let start = request.start_time.or(current.start_time);
        let end = request.end_time.or(current.end_time);
        let is_billable = request.is_billable.unwrap_or(current.is_billable);
        // PMS-395: worked time precedence - explicit `worked_minutes` >
        // `duration_minutes` > derived (start, end) > the entry's current
        // worked figure. This is the actual time spent and is never rounded.
        let worked = if let Some(w) = request.worked_minutes {
            w
        } else if let Some(d) = request.duration_minutes {
            d
        } else if let (Some(s), Some(e)) = (start, end) {
            let m = (e - s).num_minutes();
            if m < 0 {
                return Err(AppError::BadRequest(
                    "end_time must be after start_time".to_string(),
                ));
            }
            m as i32
        } else {
            current.worked_minutes
        };
        let hourly_rate = request.hourly_rate.or(current.hourly_rate);

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Write-side tenant validation on update, mirroring create_time_entry:
        // the UPDATE sets ticket_id straight from the request body and the FK
        // only checks existence, not tenant ownership, so a re-association could
        // otherwise point a time entry at another tenant's ticket. RLS hides the
        // row on read-back, but reject up front so the link is never written
        // (PMS-315 review hardening; same fix applied to mileage_entries).
        if let Some(ticket_id) = request.ticket_id {
            assert_ticket_in_tenant(&mut *tx, tenant_id, ticket_id).await?;
        }
        // The UPDATE binds ticket_id / project_id straight from the request, so
        // re-derive work_category from those same post-update values (PMS-394).
        let work_category = derive_work_category(
            request.work_category.as_deref(),
            request.ticket_id,
            request.project_id,
        )?;
        // PMS-942: the kind is set once, at create, and an update cannot change
        // it - there is no `entry_kind` or `company_id` on the update request,
        // so an entry cannot be moved between the MSP's books and a client's by
        // editing it. What an update CAN do is attach a ticket to what was
        // employee time, which is the same contradiction stated the other way
        // round, so it is refused here rather than by the constraint.
        let kind = resolve_entry_kind(EntryKindInput {
            requested: Some(&current.entry_kind),
            company_id: current.company_id,
            own_company_id: None,
            ticket_id: request.ticket_id,
            project_id: request.project_id,
            task_id: request.task_id,
            contract_id: None,
            is_billable,
        })?;
        let is_billable = kind.billable;
        // PMS-395: resolve billable minutes. An explicit value wins; otherwise
        // preserve any previously-stored value so a partial edit does not wipe
        // a hand-set billable figure; failing both, default to the rounded
        // worked time for billable entries (0 for non-billable).
        let billable = if !kind.billable {
            0
        } else {
            match request.billable_minutes.or(current.billable_minutes) {
                Some(b) => b,
                None => {
                    let rounding = default_rounding_rule(&mut *tx, tenant_id).await?;
                    derive_billable_minutes(worked, true, rounding.as_ref())
                }
            }
        };
        // total_amount is priced on billable minutes, only when billable.
        let total = if is_billable {
            hourly_rate.map(|r| r * Decimal::from(billable) / Decimal::from(60))
        } else {
            None
        };
        // PMS-396: enforce the per-day cap against the TARGET day (the entry may
        // be moving to a different date), excluding this row from the day sum so
        // an in-place edit is measured against its peers, not itself. The SUM
        // runs inside `tx` for consistency with the UPDATE. The cap is on worked
        // (actual) time, not billed time.
        let target_date = request.date.unwrap_or(current.date);
        let cap_minutes =
            crate::modules::settings::read_max_minutes_per_day(&self.db, tenant_id).await?;
        let existing =
            day_minutes_excluding(&mut *tx, tenant_id, current.user_id, target_date, Some(id))
                .await?;
        enforce_day_cap(existing, worked, cap_minutes)?;
        let affected = sqlx::query(
            r#"
            UPDATE time_entries SET
                date              = COALESCE($3, date),
                start_time        = $4,
                end_time          = $5,
                duration_minutes  = $6,
                worked_minutes    = $16,
                billable_minutes  = $17,
                work_type_id      = COALESCE($7, work_type_id),
                ticket_id         = $8,
                project_id        = $9,
                notes             = COALESCE($10, notes),
                is_billable       = $11,
                hourly_rate       = $12,
                total_amount      = $13,
                task_id           = COALESCE($14, task_id),
                work_category     = $15,
                billing_status    = $18,
                updated_at        = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(request.date)
        .bind(start)
        .bind(end)
        .bind(worked)
        .bind(request.work_type_id)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(&request.notes)
        .bind(is_billable)
        .bind(hourly_rate)
        .bind(total)
        .bind(request.task_id)
        .bind(&work_category)
        .bind(worked)
        .bind(billable)
        // PMS-944: keep invoiceability in step with billability. Turning an
        // entry non-billable has to take it back out of the invoiceable set,
        // or the row keeps the `ready_to_bill` it was created with and is
        // billed anyway. Passing the current status is what protects an
        // already-`billed` entry from being re-armed.
        .bind(resolve_billing_status(
            is_billable,
            Some(current.billing_status),
        ))
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Time entry".to_string()));
        }
        tx.commit().await?;
        // PMS-951: an edit re-draws from scratch rather than adjusting. Give
        // back exactly what this entry took, from the period it took it from,
        // and then draw again on the new figures. That is correct for every
        // edit without a case for each: a duration change, a flip to
        // non-billable, and a date that moves into another billing period all
        // fall out of it. Adjusting by a delta instead would need the split
        // between applied and overage recomputed against a balance that has
        // moved since, which is the arithmetic that gets one case wrong.
        self.release_for_entry(tenant_id, id).await?;
        self.consume_for_entry(tenant_id, id).await?;
        self.get_time_entry(tenant_id, id).await
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_time_entry(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        // PMS-951: before the row goes, because the row is where the record of
        // what it drew lives. Deleting first would leave the contract short by
        // hours nothing can account for any more.
        self.release_for_entry(tenant_id, id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let affected = sqlx::query("DELETE FROM time_entries WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Time entry".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    // ========================================================================
    // PMS-46 timesheets (aggregate over time_entries)
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_timesheets(
        &self,
        tenant_id: TenantId,
        filter: &TimesheetFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TimesheetSummaryResponse>, u64)> {
        // PMS-506: validate the status filter once up front so a
        // malformed query parameter 422s before the SQL even builds.
        let status_filter = match filter.status.as_deref().map(str::trim) {
            None | Some("") | Some("all") => None,
            Some("pending") => Some("pending"),
            Some("approved") => Some("approved"),
            Some("rejected") => Some("rejected"),
            Some(other) => {
                return Err(AppError::BadRequest(format!(
                    "Unknown timesheet status filter `{other}`; expected one of pending | approved | rejected | all",
                )));
            }
        };

        // PMS-506: resolve the date span. `from`/`to` (Monday-aligned
        // inclusive range) override the legacy `week` field; missing
        // `to` defaults to `from` so a single-week call still works.
        // Cap the span at 26 weeks to keep the scan bounded.
        const MAX_RANGE_WEEKS: i64 = 26;
        let date_span = if let Some(from_anchor) = filter.from {
            let from = monday_anchor(from_anchor);
            let to_anchor = filter.to.unwrap_or(from_anchor);
            let to = monday_anchor(to_anchor);
            if to < from {
                return Err(AppError::BadRequest(
                    "`to` must be on or after `from`".to_string(),
                ));
            }
            let span_weeks = (to - from).num_days() / 7 + 1;
            if span_weeks > MAX_RANGE_WEEKS {
                return Err(AppError::BadRequest(format!(
                    "Timesheet range capped at {MAX_RANGE_WEEKS} weeks; got {span_weeks}"
                )));
            }
            Some((from, to))
        } else {
            None
        };

        // Anchor week_start to Monday. Postgres DATE_TRUNC('week', ...)
        // does ISO week (Monday-start) by default.
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut idx = 2;
        if filter.user_id.is_some() {
            conditions.push(format!("user_id = ${idx}"));
            idx += 1;
        }
        if let Some((_, _)) = date_span {
            // Inclusive range scan: `date >= from` AND
            // `date < to + 7d` so the week that contains `to` is
            // included.
            conditions.push(format!(
                "date >= ${idx}::date \
                 AND date < (${}::date + INTERVAL '7 days')::date",
                idx + 1
            ));
            idx += 2;
        } else if filter.week.is_some() {
            conditions.push(format!(
                "date >= DATE_TRUNC('week', ${idx}::date)::date \
                 AND date < (DATE_TRUNC('week', ${idx}::date) + INTERVAL '7 days')::date"
            ));
            idx += 1;
        }
        let where_clause = conditions.join(" AND ");
        // HAVING filter on the rolled status. Cheaper than a subquery
        // because the GROUP BY already exists; nothing to do when
        // status_filter is None.
        let having_clause = if status_filter.is_some() {
            "HAVING CASE \
                 WHEN BOOL_OR(approval_status = 'rejected') THEN 'rejected' \
                 WHEN BOOL_AND(approval_status = 'approved') THEN 'approved' \
                 WHEN BOOL_OR(approval_status = 'pending') THEN 'pending' \
                 ELSE 'draft' \
             END = $"
                .to_string()
                + &idx.to_string()
        } else {
            String::new()
        };
        let status_placeholder = if status_filter.is_some() {
            let p = idx;
            idx += 1;
            Some(p)
        } else {
            None
        };
        let _ = status_placeholder; // already substituted into having_clause
        let limit_placeholder = idx;
        let offset_placeholder = idx + 1;
        let query = format!(
            r#"
            SELECT
                user_id,
                DATE_TRUNC('week', date)::date AS week_start,
                -- PMS-395: total_minutes sums worked (actual) time;
                -- billable_minutes sums the independent billed figure. Both
                -- fall back to duration_minutes for legacy rows that predate
                -- the worked/billable backfill.
                SUM(COALESCE(worked_minutes, duration_minutes))::bigint AS total_minutes,
                SUM(COALESCE(
                    billable_minutes,
                    CASE WHEN is_billable
                         THEN COALESCE(worked_minutes, duration_minutes)
                         ELSE 0 END
                ))::bigint AS billable_minutes,
                COUNT(*)::bigint AS entry_count,
                CASE
                    WHEN BOOL_OR(approval_status = 'rejected') THEN 'rejected'
                    WHEN BOOL_AND(approval_status = 'approved') THEN 'approved'
                    WHEN BOOL_OR(approval_status = 'pending') THEN 'pending'
                    ELSE 'draft'
                END AS approval_status,
                -- PMS-506: surface the decision audit so the history
                -- view can label "Approved by X on Y" / "Rejected
                -- because Z". approve_week / reject_week run a single
                -- UPDATE per week, so approved_at + approved_by_id +
                -- rejection_reason are identical across the rolled
                -- rows; take the most-recent non-NULL via ARRAY_AGG +
                -- FILTER.
                MAX(approved_at) AS decided_at,
                (ARRAY_AGG(approved_by_id) FILTER (WHERE approved_by_id IS NOT NULL))[1]
                    AS decided_by_id,
                (ARRAY_AGG(rejection_reason) FILTER (
                    WHERE rejection_reason IS NOT NULL AND rejection_reason <> ''
                ))[1] AS rejection_reason
            FROM time_entries
            WHERE {where_clause}
            GROUP BY user_id, DATE_TRUNC('week', date)
            {having_clause}
            ORDER BY week_start DESC, user_id
            LIMIT ${limit_placeholder} OFFSET ${offset_placeholder}
            "#
        );
        // Count distinct (user_id, week) groups matching the same WHERE
        // + HAVING.
        let count_query = format!(
            r#"
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM time_entries
                WHERE {where_clause}
                GROUP BY user_id, DATE_TRUNC('week', date)
                {having_clause}
            ) AS s
            "#
        );
        let mut q = sqlx::query_as::<_, TimesheetRow>(&query).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(uid) = filter.user_id {
            q = q.bind(uid);
            cq = cq.bind(uid);
        }
        if let Some((from, to)) = date_span {
            // Bound to twice: the WHERE substitutes both `${idx}` (from)
            // and `${idx+1}` (to) so each binding consumes one slot.
            q = q.bind(from).bind(to);
            cq = cq.bind(from).bind(to);
        } else if let Some(w) = filter.week {
            q = q.bind(w);
            cq = cq.bind(w);
        }
        if let Some(s) = status_filter {
            q = q.bind(s);
            cq = cq.bind(s);
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&mut *tx)
            .await?;
        let total = cq.fetch_one(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    // ========================================================================
    // PMS-47 timesheet submit (state transition over the week's entries)
    // ========================================================================

    /// `timesheet_id` is interpreted as a `(user_id, week_start)` pair
    /// composite via two query params; for the path-based endpoint the
    /// route handler unpacks `user_id_week-anchor` into the pair.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn submit_timesheet(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        week_start: NaiveDate,
    ) -> AppResult<TimesheetSummaryResponse> {
        let anchor = monday_anchor(week_start);
        let week_end = anchor + chrono::Duration::days(7);

        // Move every non-approved entry in the week to 'pending'. An empty or
        // already-approved week is not an error (decision: zeroed-summary
        // everywhere); we just return the current week summary.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE time_entries
            SET approval_status = 'pending',
                updated_at      = NOW()
            WHERE tenant_id = $1
              AND user_id   = $2
              AND date     >= $3
              AND date      < $4
              AND approval_status NOT IN ('approved')
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.week_summary(tenant_id, user_id, anchor).await
    }

    /// Withdraw a submitted timesheet: move every still-pending entry in the
    /// week back to 'draft' so the owner can edit and resubmit. Refuses once
    /// any entry in the week has been approved (PMS-183) - an approved week is
    /// past the point of withdrawal, because a manager has signed it off.
    /// Owner-only is enforced at the route.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn withdraw_timesheet(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        week_start: NaiveDate,
    ) -> AppResult<TimesheetSummaryResponse> {
        let anchor = monday_anchor(week_start);
        let week_end = anchor + chrono::Duration::days(7);

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let approved_exists: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                 SELECT 1 FROM time_entries
                 WHERE tenant_id = $1 AND user_id = $2
                   AND date >= $3 AND date < $4
                   AND approval_status = 'approved'
               )"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .fetch_one(&mut *tx)
        .await?;
        if approved_exists {
            return Err(AppError::Conflict(
                "Cannot withdraw an approved timesheet".to_string(),
            ));
        }

        sqlx::query(
            r#"
            UPDATE time_entries
            SET approval_status = 'draft',
                updated_at      = NOW()
            WHERE tenant_id = $1
              AND user_id   = $2
              AND date     >= $3
              AND date      < $4
              AND approval_status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.week_summary(tenant_id, user_id, anchor).await
    }

    /// Approve every pending entry in the user's week. Manager+ only
    /// (enforced at the route). Idempotent: re-approving an approved week is
    /// a no-op that returns the same summary.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn approve_timesheet(
        &self,
        tenant_id: TenantId,
        approver_id: Uuid,
        user_id: Uuid,
        week_start: NaiveDate,
    ) -> AppResult<TimesheetSummaryResponse> {
        let anchor = monday_anchor(week_start);
        let week_end = anchor + chrono::Duration::days(7);
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // RETURNING the rows that actually transitioned (approval_status was
        // 'pending') gives us exactly the set to consume hours for, and the
        // `pending` guard makes re-approval idempotent: a second call returns
        // no rows, so consume_hours is not double-counted (PMS-405).
        let approved: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            UPDATE time_entries
            SET approval_status = 'approved',
                approved_by_id  = $5,
                approved_at     = NOW(),
                -- PMS-944: approval no longer touches `billing_status`. PMS-144
                -- had it flip billable entries to `ready_to_bill` here, which
                -- made countersigning a timesheet the only route to an invoice;
                -- an entry is now armed at creation instead. Approval keeps its
                -- own lifecycle for the timesheet and is not a billing fact.
                updated_at      = NOW()
            WHERE tenant_id = $1
              AND user_id   = $2
              AND date     >= $3
              AND date      < $4
              AND approval_status = 'pending'
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .bind(approver_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let _ = approved.len();
        // PMS-951: approval is NOT the consumption point any more, and must not
        // draw a second time. PMS-405 put it here because approval was then the
        // moment an entry became real; PMS-944 moved that to creation, and
        // PMS-943 gated approval behind the timesheets module, so leaving it
        // here meant a tenant with timesheets off never drew an hour and a
        // tenant with them on drew every hour twice - once at creation, once at
        // approval - the moment `contract_id` started being set.

        self.week_summary(tenant_id, user_id, anchor).await
    }

    /// PMS-951: draw this entry's hours against its contract, once.
    ///
    /// `hours_consumed IS NULL` is the claim, so a retry, an edit or a second
    /// call cannot draw the same hours twice. Recording the APPLIED hours and
    /// the balance row they came out of is what lets [`Self::release_for_entry`]
    /// give back exactly what was taken, from exactly the period that gave it.
    ///
    /// An entry with no contract, no billable flag, or no duration is a no-op,
    /// which is most entries: only client work against a company holding a
    /// block-hours contract draws anything.
    async fn consume_for_entry(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let row: Option<ConsumeCandidateRow> = sqlx::query_as(
            r#"SELECT contract_id, duration_minutes, date, is_billable, entry_kind
               FROM time_entries
               WHERE tenant_id = $1 AND id = $2 AND hours_consumed IS NULL"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        let Some(row) = row else { return Ok(()) };
        let Some(contract_id) = row.contract_id else {
            return Ok(());
        };
        if !row.is_billable.unwrap_or(false) || row.entry_kind != ENTRY_KIND_CLIENT {
            return Ok(());
        }
        let hours = Decimal::from(row.duration_minutes) / Decimal::from(60);
        if hours <= Decimal::ZERO {
            return Ok(());
        }
        let when = row
            .date
            .and_hms_opt(0, 0, 0)
            .map(|naive| naive.and_utc())
            .unwrap_or_else(Utc::now);

        let contracts = crate::modules::contracts::ContractsService::new(self.db.clone());
        let outcome = contracts
            .consume_hours(tenant_id, contract_id, hours, when)
            .await?;

        // The stamp is claimed, not written: `hours_consumed IS NULL` again, so
        // two concurrent creates for one id cannot both record a draw.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"UPDATE time_entries
               SET hours_consumed = $3, hours_balance_id = $4, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2 AND hours_consumed IS NULL"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(outcome.hours_applied)
        .bind(outcome.balance_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        if outcome.overage_hours > Decimal::ZERO {
            tracing::info!(
                contract_id = %contract_id,
                overage_hours = %outcome.overage_hours,
                overage_amount = %outcome.overage_amount,
                balance_id = %outcome.balance_id,
                "logged time produced contract hour overage"
            );
        }
        Ok(())
    }

    /// PMS-951: give back what this entry drew, and forget that it drew.
    ///
    /// Called before an edit re-draws and before a delete removes the row, so
    /// an entry whose duration, billability or date changed does not leave the
    /// old figure standing against the contract. Exact, because the entry
    /// recorded the applied hours and the balance row rather than leaving them
    /// to be re-derived from a duration that has since changed.
    async fn release_for_entry(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let claimed: Option<(Decimal, Option<Uuid>)> = sqlx::query_as(
            r#"UPDATE time_entries
               SET hours_consumed = NULL, hours_balance_id = NULL, updated_at = NOW()
               WHERE tenant_id = $1 AND id = $2 AND hours_consumed IS NOT NULL
               RETURNING hours_consumed, hours_balance_id"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        // RETURNING the pre-UPDATE values is what makes this safe to race: only
        // the call that actually cleared the stamp gets a row, so two of them
        // cannot both credit the same hours back.
        let Some((applied, Some(balance_id))) = claimed else {
            return Ok(());
        };
        let contracts = crate::modules::contracts::ContractsService::new(self.db.clone());
        contracts
            .release_hours(tenant_id, balance_id, applied)
            .await
    }

    /// Reject every pending entry in the user's week with a reason. Manager+
    /// only (enforced at the route).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn reject_timesheet(
        &self,
        tenant_id: TenantId,
        reviewer_id: Uuid,
        user_id: Uuid,
        week_start: NaiveDate,
        reason: &str,
    ) -> AppResult<TimesheetSummaryResponse> {
        let anchor = monday_anchor(week_start);
        let week_end = anchor + chrono::Duration::days(7);
        // approved_by_id here records the LAST REVIEWER, not "the approver".
        // No consumer reads time_entries.approved_by_id as an approval flag
        // (verified: only calendar.time_off reads a column of that name), so
        // setting it on a rejection is safe and captures who reviewed.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE time_entries
            SET approval_status  = 'rejected',
                rejection_reason = $5,
                approved_by_id   = $6,
                approved_at      = NOW(),
                updated_at       = NOW()
            WHERE tenant_id = $1
              AND user_id   = $2
              AND date     >= $3
              AND date      < $4
              AND approval_status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(anchor)
        .bind(week_end)
        .bind(reason)
        .bind(reviewer_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.week_summary(tenant_id, user_id, anchor).await
    }

    /// Current week summary for a user, or a zeroed `pending` summary when the
    /// week has no entries. Keeps submit/approve/reject responses consistent
    /// on empty weeks (no 404s).
    async fn week_summary(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        anchor: NaiveDate,
    ) -> AppResult<TimesheetSummaryResponse> {
        let filter = TimesheetFilter {
            user_id: Some(user_id),
            week: Some(anchor),
            status: None,
            from: None,
            to: None,
        };
        // A single user_id+week pair yields at most one row; the default
        // pagination window is more than enough.
        let pagination = PaginationParams::default();
        let (summaries, _total) = self
            .list_timesheets(tenant_id, &filter, &pagination)
            .await?;
        Ok(summaries
            .into_iter()
            .find(|s| s.user_id == user_id && s.week_start == anchor)
            .unwrap_or_else(|| TimesheetSummaryResponse {
                user_id,
                week_start: anchor,
                total_minutes: 0,
                billable_minutes: 0,
                entry_count: 0,
                approval_status: "draft".to_string(),
                decided_by_id: None,
                decided_at: None,
                rejection_reason: None,
            }))
    }

    // ========================================================================
    // PMS-48 active timers
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_active_timers(
        &self,
        tenant_id: TenantId,
        user_id: Option<Uuid>,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<ActiveTimerResponse>, u64)> {
        let (sql, count_sql, has_user) = if user_id.is_some() {
            (
                "SELECT id, user_id, ticket_id, project_id, company_id, work_type_id, notes, started_at \
                 FROM active_timers WHERE tenant_id = $1 AND user_id = $2 \
                 ORDER BY started_at DESC LIMIT $3 OFFSET $4",
                "SELECT COUNT(*) FROM active_timers WHERE tenant_id = $1 AND user_id = $2",
                true,
            )
        } else {
            (
                "SELECT id, user_id, ticket_id, project_id, company_id, work_type_id, notes, started_at \
                 FROM active_timers WHERE tenant_id = $1 \
                 ORDER BY started_at DESC LIMIT $2 OFFSET $3",
                "SELECT COUNT(*) FROM active_timers WHERE tenant_id = $1",
                false,
            )
        };
        let mut q = sqlx::query_as::<_, ActiveTimerRow>(sql).bind(tenant_id);
        let mut cq = sqlx::query_scalar::<_, i64>(count_sql).bind(tenant_id);
        if has_user {
            q = q.bind(user_id.unwrap());
            cq = cq.bind(user_id.unwrap());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = q
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&mut *tx)
            .await?;
        let total = cq.fetch_one(&mut *tx).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn start_timer(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        request: &StartTimerRequest,
    ) -> AppResult<ActiveTimerResponse> {
        // UNIQUE(user_id) on active_timers means we either upsert or
        // reject. We reject so the user explicitly stops + re-starts;
        // silent replacement loses the prior elapsed time.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM active_timers WHERE tenant_id = $1 AND user_id = $2)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            return Err(AppError::Conflict(
                "User already has an active timer; stop it first".to_string(),
            ));
        }

        // Validate any supplied references belong to the tenant before we
        // persist a timer that points at them.
        if let Some(ticket_id) = request.ticket_id {
            assert_ticket_in_tenant(&mut *tx, tenant_id, ticket_id).await?;
        }
        if let Some(company_id) = request.company_id {
            assert_company_in_tenant(&mut *tx, tenant_id, company_id).await?;
        }
        if let Some(work_type_id) = request.work_type_id {
            fetch_work_type_defaults(&mut *tx, tenant_id, work_type_id).await?;
        }

        let id = Uuid::new_v4();
        let started_at: chrono::DateTime<Utc> = match sqlx::query_scalar(
            r#"
            INSERT INTO active_timers
                (id, tenant_id, user_id, ticket_id, project_id, company_id,
                 work_type_id, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING started_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(request.ticket_id)
        .bind(request.project_id)
        .bind(request.company_id)
        .bind(request.work_type_id)
        .bind(&request.notes)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(ts) => ts,
            // TOCTOU: another request may have inserted between the exists
            // check above and here. UNIQUE(user_id) backs us; surface the
            // race as a clean Conflict instead of a raw 500.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(AppError::Conflict(
                    "User already has an active timer; stop it first".to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        tx.commit().await?;

        Ok(ActiveTimerResponse {
            id,
            user_id,
            ticket_id: request.ticket_id,
            project_id: request.project_id,
            company_id: request.company_id,
            work_type_id: request.work_type_id,
            notes: request.notes.clone(),
            started_at,
        })
    }

    /// Stop a timer: removes the `active_timers` row and creates a
    /// `time_entries` row covering the elapsed window.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn stop_timer(
        &self,
        tenant_id: TenantId,
        timer_id: Uuid,
    ) -> AppResult<TimeEntryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let timer: Option<ActiveTimerRow> = sqlx::query_as(
            "SELECT id, user_id, ticket_id, project_id, company_id, work_type_id, notes, started_at \
             FROM active_timers WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(timer_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(timer) = timer else {
            return Err(AppError::NotFound("Active timer".to_string()));
        };

        let now = Utc::now();
        let raw = (now - timer.started_at).num_minutes().max(1) as i32;

        // Active timer might not carry work_type_id / company_id; the
        // schema requires both on time_entries. Fall back to first
        // active work type and first company on the timer user's tenant.
        let work_type_id = match timer.work_type_id {
            Some(v) => v,
            None => sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM work_types WHERE tenant_id = $1 AND is_active = TRUE ORDER BY sort_order LIMIT 1",
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::Configuration(
                    "Cannot stop timer: tenant has no active work_types and timer set none"
                        .to_string(),
                )
            })?,
        };
        // PMS-942: a company if one can be found, and no company if not.
        //
        // This used to 400 with "Cannot stop timer without an inferable
        // company_id" when the timer named neither a company nor a ticket,
        // which meant a timer started for admin work could not be stopped at
        // all: the only way out was to discard the elapsed time. That was the
        // NOT NULL on `company_id` speaking through the service. The entry is
        // employee time, and employee time names no client.
        let company_id = match timer.company_id {
            Some(v) => Some(v),
            None => match timer.ticket_id {
                // Short-circuit when there is no ticket either, rather than
                // querying `tickets` by Uuid::nil() (which never matches and is
                // wasted work).
                None => None,
                Some(ticket_id) => {
                    sqlx::query_scalar::<_, Uuid>(
                        "SELECT company_id FROM tickets WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(tenant_id)
                    .bind(ticket_id)
                    .fetch_optional(&mut *tx)
                    .await?
                }
            },
        };

        // Derive billing from the resolved, tenant-scoped work type and apply
        // the tenant default rounding rule to the elapsed minutes, so a
        // stopped timer is priced consistently with a manual entry.
        let defaults = fetch_work_type_defaults(&mut *tx, tenant_id, work_type_id).await?;
        let kind = resolve_entry_kind(EntryKindInput {
            requested: None,
            company_id,
            own_company_id: own_company_id(&mut *tx, tenant_id).await?,
            ticket_id: timer.ticket_id,
            project_id: timer.project_id,
            task_id: None,
            contract_id: None,
            is_billable: defaults.default_billable,
        })?;
        let duration = match default_rounding_rule(&mut *tx, tenant_id).await? {
            Some(rule) => apply_rounding(raw, &rule),
            None => raw,
        };
        let (hourly_rate, total) = resolve_billing(None, kind.billable, &defaults, duration);
        // PMS-951: a stopped timer draws on the same terms as time typed in.
        let contract_id = block_hours_contract_for(
            &mut *tx,
            tenant_id,
            company_id,
            now.date_naive(),
            kind.kind,
            kind.billable,
        )
        .await?;

        let entry_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO time_entries (
                id, tenant_id, user_id, date, start_time, end_time,
                duration_minutes, work_type_id, ticket_id, project_id,
                company_id, notes, is_billable, hourly_rate, total_amount,
                entry_kind, billing_status, contract_id
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )
            "#,
        )
        .bind(entry_id)
        .bind(tenant_id)
        .bind(timer.user_id)
        .bind(now.date_naive())
        .bind(timer.started_at.time())
        .bind(now.time())
        .bind(duration)
        .bind(work_type_id)
        .bind(timer.ticket_id)
        .bind(timer.project_id)
        .bind(company_id)
        .bind(&timer.notes)
        .bind(kind.billable)
        .bind(hourly_rate)
        .bind(total)
        .bind(kind.kind)
        // PMS-944: same rule as the manual path. A stopped timer is time that
        // was worked, so it is invoiceable on the same terms as time typed in.
        .bind(resolve_billing_status(kind.billable, None))
        .bind(contract_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM active_timers WHERE id = $1")
            .bind(timer_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        self.consume_for_entry(tenant_id, entry_id).await?;
        self.get_time_entry(tenant_id, entry_id).await
    }

    // ========================================================================
    // PMS-49 time rounding rules
    // ========================================================================

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_rounding_rules(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<TimeRoundingRuleResponse>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM time_rounding_rules WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;

        let rows = sqlx::query_as::<_, RoundingRuleRow>(
            r#"
            SELECT id, name, increment_minutes, rounding_method, minimum_minutes, is_default
            FROM time_rounding_rules
            WHERE tenant_id = $1
            ORDER BY is_default DESC, name
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_rounding_rule(
        &self,
        tenant_id: TenantId,
        request: &UpsertTimeRoundingRuleRequest,
        ctx: &AuditCtx,
    ) -> AppResult<TimeRoundingRuleResponse> {
        Self::validate_rounding_method(&request.rounding_method)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query("UPDATE time_rounding_rules SET is_default = FALSE WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
        }
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO time_rounding_rules
                (tenant_id, name, increment_minutes, rounding_method,
                 minimum_minutes, is_default)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(&request.name)
        .bind(request.increment_minutes)
        .bind(&request.rounding_method)
        .bind(request.minimum_minutes)
        .bind(request.is_default)
        .fetch_one(&mut *tx)
        .await?;
        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM time_rounding_rules t WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "time_rounding_rules",
            Some(id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;
        Ok(TimeRoundingRuleResponse {
            id,
            name: request.name.clone(),
            increment_minutes: request.increment_minutes,
            rounding_method: request.rounding_method.clone(),
            minimum_minutes: request.minimum_minutes,
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_rounding_rule(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertTimeRoundingRuleRequest,
    ) -> AppResult<TimeRoundingRuleResponse> {
        Self::validate_rounding_method(&request.rounding_method)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if request.is_default {
            sqlx::query(
                "UPDATE time_rounding_rules SET is_default = FALSE WHERE tenant_id = $1 AND id <> $2",
            )
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        let affected = sqlx::query(
            r#"
            UPDATE time_rounding_rules SET
                name = $3, increment_minutes = $4, rounding_method = $5,
                minimum_minutes = $6, is_default = $7, updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&request.name)
        .bind(request.increment_minutes)
        .bind(&request.rounding_method)
        .bind(request.minimum_minutes)
        .bind(request.is_default)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Time rounding rule".to_string()));
        }
        tx.commit().await?;
        Ok(TimeRoundingRuleResponse {
            id,
            name: request.name.clone(),
            increment_minutes: request.increment_minutes,
            rounding_method: request.rounding_method.clone(),
            minimum_minutes: request.minimum_minutes,
            is_default: request.is_default,
        })
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_rounding_rule(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let affected =
            sqlx::query("DELETE FROM time_rounding_rules WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        if affected == 0 {
            return Err(AppError::NotFound("Time rounding rule".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    fn validate_rounding_method(method: &str) -> AppResult<()> {
        match method {
            "up" | "down" | "nearest" => Ok(()),
            other => Err(AppError::BadRequest(format!(
                "rounding_method {other:?} invalid; expected up | down | nearest"
            ))),
        }
    }
}

// ============================================================================
// Shared resolve helpers (tenant validation + billing derivation + rounding)
// ============================================================================

struct WorkTypeDefaults {
    default_rate: Option<Decimal>,
    default_billable: bool,
}

/// Tenant-scoped work-type fetch returning its billing defaults. `NotFound`
/// when the work type does not belong to `tenant_id` - this doubles as
/// write-side tenant validation, closing the cross-tenant attach vector
/// (FKs check existence, not ownership).
async fn fetch_work_type_defaults<'e, E>(
    exec: E,
    tenant_id: TenantId,
    work_type_id: Uuid,
) -> AppResult<WorkTypeDefaults>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(Option<Decimal>, bool)> = sqlx::query_as::<_, (Option<Decimal>, bool)>(
        r#"
        SELECT default_rate, COALESCE(default_billable, TRUE) AS default_billable
        FROM work_types
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(work_type_id)
    .fetch_optional(exec)
    .await?;
    let (default_rate, default_billable) =
        row.ok_or_else(|| AppError::NotFound("Work type".to_string()))?;
    Ok(WorkTypeDefaults {
        default_rate,
        default_billable,
    })
}

/// Assert a ticket belongs to the tenant; return its `company_id` so the
/// caller can both validate and infer company. `NotFound` cross-tenant.
async fn assert_ticket_in_tenant<'e, E>(
    exec: E,
    tenant_id: TenantId,
    ticket_id: Uuid,
) -> AppResult<Uuid>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, Uuid>("SELECT company_id FROM tickets WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(exec)
        .await?
        .ok_or_else(|| AppError::NotFound("Ticket".to_string()))
}

/// Assert a company belongs to the tenant. `NotFound` cross-tenant.
async fn assert_company_in_tenant<'e, E>(
    exec: E,
    tenant_id: TenantId,
    company_id: Uuid,
) -> AppResult<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let found: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM companies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(company_id)
            .fetch_optional(exec)
            .await?;
    found
        .map(|_| ())
        .ok_or_else(|| AppError::NotFound("Company".to_string()))
}

/// PMS-942: the two values of `time_entries.entry_kind`.
pub(crate) const ENTRY_KIND_CLIENT: &str = "client";
pub(crate) const ENTRY_KIND_EMPLOYEE: &str = "employee";

/// What a resolved entry kind implies for the rest of the row.
///
/// Employee time is the MSP's own: it names no client work and can never reach
/// a client invoice, so the billing fields are settled here rather than being
/// taken from the request and filtered out again at every read.
pub(crate) struct ResolvedKind {
    pub kind: &'static str,
    pub billable: bool,
}

/// Decide whether an entry is a client's work or the employee's own.
///
/// An explicit `entry_kind` wins, and is then checked against the rest of the
/// request rather than trusted: `employee` with a ticket on it is a
/// contradiction the database constraint would reject anyway, and a 400 naming
/// the field is a better answer than a 500 naming the constraint.
///
/// Derived, the rule reads off what the entry is attached to. A ticket, a
/// project, a task or a contract is client work whatever else is set. Failing
/// those, the tenant's own internal company (PMS-413) is the signal MAPPS-243
/// already sends for a General entry, so it means employee time - which is what
/// lets today's client get the new behaviour without changing a line. No
/// company at all is employee time, because there is no client to bill.
/// Anything else, meaning a real customer company with no work item, stays
/// client work: a billable phone call logged without a ticket is the client's
/// time, and `work_category = 'general'` does not say otherwise.
pub(crate) struct EntryKindInput<'a> {
    /// What the caller asked for, if anything.
    pub requested: Option<&'a str>,
    pub company_id: Option<Uuid>,
    /// The tenant's own internal company (PMS-413), or `None` on a tenant that
    /// has none. Compared against `company_id`, never assumed.
    pub own_company_id: Option<Uuid>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub task_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub is_billable: bool,
}

pub(crate) fn resolve_entry_kind(input: EntryKindInput<'_>) -> AppResult<ResolvedKind> {
    let EntryKindInput {
        requested,
        company_id,
        own_company_id,
        ticket_id,
        project_id,
        task_id,
        contract_id,
        is_billable,
    } = input;
    let has_client_work =
        ticket_id.is_some() || project_id.is_some() || task_id.is_some() || contract_id.is_some();
    let derived = if has_client_work {
        ENTRY_KIND_CLIENT
    } else if company_id.is_none() || (own_company_id.is_some() && company_id == own_company_id) {
        ENTRY_KIND_EMPLOYEE
    } else {
        ENTRY_KIND_CLIENT
    };
    let kind = match requested.map(str::trim) {
        None | Some("") => derived,
        Some(ENTRY_KIND_CLIENT) => ENTRY_KIND_CLIENT,
        Some(ENTRY_KIND_EMPLOYEE) => ENTRY_KIND_EMPLOYEE,
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "entry_kind must be one of client, employee (got {other:?})"
            )));
        }
    };
    if kind == ENTRY_KIND_EMPLOYEE && has_client_work {
        return Err(AppError::BadRequest(
            "Employee time carries no ticket, project, task or contract; it is the MSP's own time, not a client's".to_string(),
        ));
    }
    if kind == ENTRY_KIND_CLIENT && company_id.is_none() {
        return Err(AppError::BadRequest(
            "Client work needs a company_id; log it as employee time if it belongs to no client"
                .to_string(),
        ));
    }
    Ok(ResolvedKind {
        kind,
        // Employee time is never billable. Refused here rather than in the
        // database CHECK, because `is_billable` DEFAULTs TRUE and an overhead
        // entry logged before migration 119 may well carry it; a constraint
        // covering it would have aborted that migration.
        billable: kind == ENTRY_KIND_CLIENT && is_billable,
    })
}

/// PMS-951: the contract a piece of work draws its hours from, or `None`.
///
/// Derived from the company rather than asked for, because the contract
/// covering a piece of work follows from who it is for, and a picker in front
/// of the person logging time invites picking the wrong one.
///
/// Only client work draws: employee time has no client to bill and a
/// non-billable entry is not being charged for, so neither should come out of a
/// prepaid allotment. A company with no active block-hours contract on that
/// date gets `None`, which is most companies.
///
/// The date matters: an entry logged against last quarter draws from the
/// contract that was live then, so an expired contract still covers time worked
/// while it ran.
async fn block_hours_contract_for(
    tx: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    company_id: Option<Uuid>,
    date: chrono::NaiveDate,
    entry_kind: &str,
    is_billable: bool,
) -> AppResult<Option<Uuid>> {
    if entry_kind != ENTRY_KIND_CLIENT || !is_billable {
        return Ok(None);
    }
    let Some(company_id) = company_id else {
        return Ok(None);
    };
    // Newest first, so a renewal wins over the contract it replaced when both
    // cover the date. Tie-broken on id so the answer is the same on every run.
    let found: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT c.id
           FROM contracts c
           INNER JOIN contract_items ci
                   ON ci.contract_id = c.id AND ci.item_type = 'block_hours'
           WHERE c.tenant_id = $1
             AND c.company_id = $2
             AND c.status = 'active'
             AND c.start_date <= $3
             AND (c.end_date IS NULL OR c.end_date >= $3)
           ORDER BY c.start_date DESC, c.id
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(date)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(found)
}

/// PMS-951: the fields that decide whether an entry draws, and how much.
#[derive(sqlx::FromRow)]
struct ConsumeCandidateRow {
    contract_id: Option<Uuid>,
    duration_minutes: i32,
    date: chrono::NaiveDate,
    is_billable: Option<bool>,
    entry_kind: String,
}

/// PMS-944: whether a time entry is invoiceable, decided by the entry itself.
///
/// A billable entry is ready to bill because the work was logged, not because
/// somebody countersigned it. This is what `MileageTrackingService::create` has
/// always done; PMS-144 made time the exception by routing `ready_to_bill`
/// through weekly timesheet approval, which is the gate this issue removes. An
/// entry that is already `billed` keeps that status whatever else changes,
/// because its invoice line exists and re-arming the row would bill it twice.
pub(crate) fn resolve_billing_status(
    is_billable: bool,
    current: Option<BillingStatus>,
) -> &'static str {
    if current == Some(BillingStatus::Billed) {
        return "billed";
    }
    if is_billable {
        "ready_to_bill"
    } else {
        "not_billed"
    }
}

/// The tenant's own internal company (PMS-413), or `None` on a tenant that has
/// none. Read through the caller's tenant-scoped executor.
async fn own_company_id<'e, E>(exec: E, tenant_id: TenantId) -> AppResult<Option<Uuid>>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(
        sqlx::query_scalar::<_, Option<Uuid>>("SELECT own_company_id FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(exec)
            .await?
            .flatten(),
    )
}

/// Derive the persisted `work_category` (PMS-394) from an optional
/// client-supplied value and the presence of a ticket / project link.
///
/// When the client omits it, classify from the work item: a ticket makes it
/// `ticketed`, else a project makes it `project`, else `general` (true
/// overhead, no work item). When the client supplies it, accept any value in
/// the taxonomy but reject the contradiction of `ticketed` with no ticket so a
/// mislabelled entry never persists.
fn derive_work_category(
    requested: Option<&str>,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
) -> AppResult<String> {
    let derived = if ticket_id.is_some() {
        "ticketed"
    } else if project_id.is_some() {
        "project"
    } else {
        "general"
    };
    match requested.map(str::trim) {
        None | Some("") => Ok(derived.to_string()),
        Some(category) => {
            if !matches!(category, "ticketed" | "project" | "general") {
                return Err(AppError::BadRequest(format!(
                    "work_category must be one of ticketed, project, general (got {category:?})"
                )));
            }
            if category == "ticketed" && ticket_id.is_none() {
                return Err(AppError::BadRequest(
                    "work_category 'ticketed' requires a ticket_id".to_string(),
                ));
            }
            Ok(category.to_string())
        }
    }
}

/// Sum a user's already-logged minutes for one calendar date, optionally
/// excluding a single entry (the row being edited). The SUM is read through the
/// caller's tenant-scoped executor so it stays consistent with the INSERT/UPDATE
/// in the same transaction (PMS-396). `exclude_id` of `None` matches every row.
async fn day_minutes_excluding<'e, E>(
    exec: E,
    tenant_id: TenantId,
    user_id: Uuid,
    date: NaiveDate,
    exclude_id: Option<Uuid>,
) -> AppResult<i64>
where
    E: sqlx::PgExecutor<'e>,
{
    let sum: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(duration_minutes), 0)::bigint
        FROM time_entries
        WHERE tenant_id = $1 AND user_id = $2 AND date = $3
          AND ($4::uuid IS NULL OR id <> $4)
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(date)
    .bind(exclude_id)
    .fetch_one(exec)
    .await?;
    Ok(sum)
}

/// Reject when adding `new_minutes` to a day that already holds `existing` would
/// exceed the per-day `cap_minutes` (PMS-396). The error names the cap in hours
/// and the minutes still available for the day before this entry.
fn enforce_day_cap(existing: i64, new_minutes: i32, cap_minutes: i32) -> AppResult<()> {
    let total = existing + new_minutes as i64;
    if total > cap_minutes as i64 {
        let remaining = (cap_minutes as i64 - existing).max(0);
        return Err(AppError::BadRequest(format!(
            "Day total would exceed the {}h/day cap ({} minutes); this entry of {} minutes leaves {} minutes for the day",
            cap_minutes / 60,
            cap_minutes,
            new_minutes,
            remaining
        )));
    }
    Ok(())
}

/// Anchor a date to the Monday of its ISO week.
fn monday_anchor(d: NaiveDate) -> NaiveDate {
    d - chrono::Duration::days(d.weekday().num_days_from_monday() as i64)
}

struct RoundingParams {
    increment_minutes: i32,
    minimum_minutes: i32,
    method: String,
}

/// Apply a tenant rounding rule to a raw duration.
///
/// BILLING-CRITICAL: the order below is load-bearing. Once entries are billed
/// against it, changing this re-prices every entry billed after the change.
/// Do not reorder without a re-pricing migration.
///
/// 1. Floor to `minimum_minutes` first (a 3-min call on a 15-min floor
///    bills 15).
/// 2. Round the floored value to `increment_minutes` per `method`.
///
/// Tie-break: an exact midpoint rounds UP (bill-favorable, MSP convention).
/// `increment_minutes <= 0` is treated as no increment rounding (floor only).
fn apply_rounding(raw_minutes: i32, rule: &RoundingParams) -> i32 {
    let floored = raw_minutes.max(rule.minimum_minutes);
    let inc = rule.increment_minutes;
    if inc <= 0 {
        return floored;
    }
    let r = floored % inc;
    if r == 0 {
        return floored;
    }
    let down = floored - r;
    match rule.method.as_str() {
        "down" => down,
        "up" => down + inc,
        // `r * 2 >= inc` makes an exact midpoint round up.
        "nearest" => {
            if r * 2 >= inc {
                down + inc
            } else {
                down
            }
        }
        // Unreachable: method validated at rule-write (validate_rounding_method).
        _ => floored,
    }
}

/// Derive the billable minutes for an entry when the caller does not supply
/// them (PMS-395). Preserves the pre-change behavior: a billable entry bills
/// the rounded worked time, a non-billable entry bills 0. Rounding only ever
/// touches this figure now, never the stored worked minutes.
fn derive_billable_minutes(
    worked_minutes: i32,
    is_billable: bool,
    rounding: Option<&RoundingParams>,
) -> i32 {
    if !is_billable {
        return 0;
    }
    match rounding {
        Some(rule) => apply_rounding(worked_minutes, rule),
        None => worked_minutes,
    }
}

/// Tenant default rounding rule, if one is configured. `None` => identity
/// (raw minutes, no rounding). Missing-rule = identity is a deliberate M1
/// choice; tracked as debt, not a silent gap.
async fn default_rounding_rule<'e, E>(
    exec: E,
    tenant_id: TenantId,
) -> AppResult<Option<RoundingParams>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(i32, i32, String)> = sqlx::query_as::<_, (i32, i32, String)>(
        r#"
        SELECT increment_minutes, COALESCE(minimum_minutes, 0), rounding_method
        FROM time_rounding_rules
        WHERE tenant_id = $1 AND is_default = TRUE
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(exec)
    .await?;
    Ok(row.map(
        |(increment_minutes, minimum_minutes, method)| RoundingParams {
            increment_minutes,
            minimum_minutes,
            method,
        },
    ))
}

/// Resolve the billable rate and total for an entry.
///
/// Rate precedence (locked, documented so an edited rate is never silently
/// overwritten by the derive step):
///   explicit request hourly_rate  >  work_type.default_rate  >  None
/// `total_amount` is computed only when the entry is billable.
fn resolve_billing(
    explicit_rate: Option<Decimal>,
    is_billable: bool,
    defaults: &WorkTypeDefaults,
    minutes: i32,
) -> (Option<Decimal>, Option<Decimal>) {
    let rate = explicit_rate.or(defaults.default_rate);
    let total = if is_billable {
        rate.map(|r| r * Decimal::from(minutes) / Decimal::from(60))
    } else {
        None
    };
    (rate, total)
}

#[derive(sqlx::FromRow)]
struct WorkTypeRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    default_billable: bool,
    default_rate: Option<Decimal>,
    is_active: bool,
    sort_order: i32,
}

impl From<WorkTypeRow> for WorkTypeResponse {
    fn from(r: WorkTypeRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            default_billable: r.default_billable,
            default_rate: r.default_rate,
            is_active: r.is_active,
            sort_order: r.sort_order,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TimeEntryRow {
    id: Uuid,
    user_id: Uuid,
    date: chrono::NaiveDate,
    start_time: Option<chrono::NaiveTime>,
    end_time: Option<chrono::NaiveTime>,
    duration_minutes: i32,
    worked_minutes: Option<i32>,
    billable_minutes: Option<i32>,
    work_type_id: Uuid,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    task_id: Option<Uuid>,
    company_id: Option<Uuid>,
    entry_kind: Option<String>,
    notes: Option<String>,
    is_billable: Option<bool>,
    billing_status: Option<String>,
    hourly_rate: Option<Decimal>,
    total_amount: Option<Decimal>,
    approval_status: Option<String>,
    work_category: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    ticket_number: Option<String>,
    ticket_title: Option<String>,
    project_name: Option<String>,
    task_title: Option<String>,
}

impl From<TimeEntryRow> for TimeEntryResponse {
    fn from(r: TimeEntryRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            date: r.date,
            start_time: r.start_time,
            end_time: r.end_time,
            duration_minutes: r.duration_minutes,
            // PMS-395: legacy rows that predate the backfill have NULL
            // worked_minutes; fall back to the duration so the worked figure
            // is always present.
            worked_minutes: r.worked_minutes.unwrap_or(r.duration_minutes),
            billable_minutes: r.billable_minutes,
            work_type_id: r.work_type_id,
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            task_id: r.task_id,
            company_id: r.company_id,
            // PMS-942: a row written before migration 119 cannot exist without
            // the column's DEFAULT, so this only ever falls back for a row read
            // through a query that forgot to select it.
            entry_kind: r
                .entry_kind
                .unwrap_or_else(|| ENTRY_KIND_CLIENT.to_string()),
            notes: r.notes,
            is_billable: r.is_billable.unwrap_or(true),
            billing_status: r
                .billing_status
                .as_deref()
                .and_then(BillingStatus::from_str)
                .unwrap_or_default(),
            hourly_rate: r.hourly_rate,
            total_amount: r.total_amount,
            approval_status: r
                .approval_status
                .as_deref()
                .and_then(ApprovalStatus::from_str)
                .unwrap_or_default(),
            work_category: r.work_category,
            created_at: r.created_at,
            updated_at: r.updated_at,
            ticket_number: r.ticket_number,
            ticket_title: r.ticket_title,
            project_name: r.project_name,
            task_title: r.task_title,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TimesheetRow {
    user_id: Uuid,
    week_start: chrono::NaiveDate,
    total_minutes: i64,
    billable_minutes: i64,
    entry_count: i64,
    approval_status: String,
    // PMS-506: rolled decision audit. NULL on pending weeks.
    decided_at: Option<chrono::DateTime<chrono::Utc>>,
    decided_by_id: Option<Uuid>,
    rejection_reason: Option<String>,
}

impl From<TimesheetRow> for TimesheetSummaryResponse {
    fn from(r: TimesheetRow) -> Self {
        Self {
            user_id: r.user_id,
            week_start: r.week_start,
            total_minutes: r.total_minutes,
            billable_minutes: r.billable_minutes,
            entry_count: r.entry_count,
            approval_status: r.approval_status,
            decided_by_id: r.decided_by_id,
            decided_at: r.decided_at,
            rejection_reason: r.rejection_reason,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ActiveTimerRow {
    id: Uuid,
    user_id: Uuid,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    company_id: Option<Uuid>,
    work_type_id: Option<Uuid>,
    notes: Option<String>,
    started_at: chrono::DateTime<Utc>,
}

impl From<ActiveTimerRow> for ActiveTimerResponse {
    fn from(r: ActiveTimerRow) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            company_id: r.company_id,
            work_type_id: r.work_type_id,
            notes: r.notes,
            started_at: r.started_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RoundingRuleRow {
    id: Uuid,
    name: String,
    increment_minutes: i32,
    rounding_method: String,
    minimum_minutes: Option<i32>,
    is_default: Option<bool>,
}

impl From<RoundingRuleRow> for TimeRoundingRuleResponse {
    fn from(r: RoundingRuleRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            increment_minutes: r.increment_minutes,
            rounding_method: r.rounding_method,
            minimum_minutes: r.minimum_minutes.unwrap_or(0),
            is_default: r.is_default.unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(increment_minutes: i32, minimum_minutes: i32, method: &str) -> RoundingParams {
        RoundingParams {
            increment_minutes,
            minimum_minutes,
            method: method.to_string(),
        }
    }

    #[test]
    fn rounding_floor_applies_before_increment() {
        // 3 raw minutes, 15-min floor, round up to 15-min increment -> 15.
        assert_eq!(apply_rounding(3, &rule(15, 15, "up")), 15);
        // Floor alone lifts a sub-minimum value even with method "down".
        assert_eq!(apply_rounding(3, &rule(15, 15, "down")), 15);
    }

    #[test]
    fn rounding_up_rounds_partial_increment_up() {
        assert_eq!(apply_rounding(16, &rule(15, 0, "up")), 30);
        // Exact multiples are untouched.
        assert_eq!(apply_rounding(30, &rule(15, 0, "up")), 30);
    }

    #[test]
    fn rounding_down_truncates_to_increment() {
        assert_eq!(apply_rounding(29, &rule(15, 0, "down")), 15);
        assert_eq!(apply_rounding(14, &rule(15, 0, "down")), 0);
    }

    #[test]
    fn rounding_nearest_midpoint_rounds_up() {
        // Exact midpoint (7.5 of 15) rounds UP per the locked tie-break.
        assert_eq!(apply_rounding(8, &rule(15, 0, "nearest")), 15);
        // Just below midpoint rounds down.
        assert_eq!(apply_rounding(7, &rule(15, 0, "nearest")), 0);
        // Just above midpoint rounds up.
        assert_eq!(apply_rounding(23, &rule(15, 0, "nearest")), 30);
    }

    #[test]
    fn rounding_zero_increment_is_floor_only() {
        assert_eq!(apply_rounding(7, &rule(0, 15, "up")), 15);
        assert_eq!(apply_rounding(40, &rule(0, 15, "up")), 40);
    }

    #[test]
    fn enforce_day_cap_allows_up_to_and_rejects_over() {
        // Exactly at the cap is allowed (8h existing + 16h new == 24h).
        assert!(enforce_day_cap(8 * 60, 16 * 60, 24 * 60).is_ok());
        // One minute over the cap is rejected.
        let err = enforce_day_cap(8 * 60, 16 * 60 + 1, 24 * 60).unwrap_err();
        match err {
            AppError::BadRequest(msg) => {
                // Message names the cap (in hours) and the remaining minutes.
                assert!(msg.contains("24h/day"), "msg names the cap: {msg}");
                assert!(
                    msg.contains("960 minutes for the day"),
                    "msg names remaining: {msg}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
        // An 18h cap rejects a day reaching 19h.
        assert!(enforce_day_cap(18 * 60, 60, 18 * 60).is_err());
        assert!(enforce_day_cap(17 * 60, 60, 18 * 60).is_ok());
    }

    #[test]
    fn resolve_billing_rate_precedence() {
        let defaults = WorkTypeDefaults {
            default_rate: Some(Decimal::from(100)),
            default_billable: true,
        };
        // Explicit rate wins over the work-type default.
        let (rate, total) = resolve_billing(Some(Decimal::from(150)), true, &defaults, 60);
        assert_eq!(rate, Some(Decimal::from(150)));
        assert_eq!(total, Some(Decimal::from(150)));
        // Falls back to the work-type default when no explicit rate.
        let (rate, total) = resolve_billing(None, true, &defaults, 30);
        assert_eq!(rate, Some(Decimal::from(100)));
        assert_eq!(total, Some(Decimal::from(50)));
        // Non-billable never produces a total, even with a known rate.
        let (rate, total) = resolve_billing(None, false, &defaults, 60);
        assert_eq!(rate, Some(Decimal::from(100)));
        assert_eq!(total, None);
    }

    // PMS-942: whose time is this.
    fn kind(
        requested: Option<&str>,
        company: Option<Uuid>,
        own: Option<Uuid>,
        ticket: Option<Uuid>,
    ) -> AppResult<ResolvedKind> {
        resolve_entry_kind(EntryKindInput {
            requested,
            company_id: company,
            own_company_id: own,
            ticket_id: ticket,
            project_id: None,
            task_id: None,
            contract_id: None,
            is_billable: true,
        })
    }

    fn billable_kind(company: Option<Uuid>, own: Option<Uuid>) -> ResolvedKind {
        resolve_entry_kind(EntryKindInput {
            requested: None,
            company_id: company,
            own_company_id: own,
            ticket_id: None,
            project_id: None,
            task_id: None,
            contract_id: None,
            is_billable: true,
        })
        .expect("a resolvable entry")
    }

    /// The rule, read off what the entry is attached to. The third case is the
    /// one the issue originally proposed to get wrong: a customer's company
    /// with no ticket is still the customer's time, and inferring "internal"
    /// from the missing ticket would take those hours off the invoice.
    #[test]
    fn the_kind_is_read_from_what_the_entry_is_attached_to() {
        let own = Uuid::new_v4();
        let client = Uuid::new_v4();
        assert_eq!(kind(None, None, Some(own), None).unwrap().kind, "employee");
        assert_eq!(
            kind(None, Some(own), Some(own), None).unwrap().kind,
            "employee",
            "the tenant's own internal company is what MAPPS-243 already sends"
        );
        assert_eq!(
            kind(None, Some(client), Some(own), None).unwrap().kind,
            "client",
            "a customer with no ticket is still a customer"
        );
        assert_eq!(
            kind(None, Some(own), Some(own), Some(Uuid::new_v4()))
                .unwrap()
                .kind,
            "client",
            "a ticket is client work whatever company the row names"
        );
    }

    /// A tenant with no internal company yet. Nothing may be compared against
    /// `None`, or every entry naming no company AND every entry naming one
    /// would collapse to the same answer.
    #[test]
    fn a_tenant_without_an_internal_company_still_classifies() {
        let client = Uuid::new_v4();
        assert_eq!(kind(None, None, None, None).unwrap().kind, "employee");
        assert_eq!(kind(None, Some(client), None, None).unwrap().kind, "client");
    }

    /// Both contradictions are refused, so the constraint in migration 119 is
    /// never the thing that reports them.
    #[test]
    fn the_contradictions_are_refused_before_the_database_sees_them() {
        let own = Uuid::new_v4();
        assert!(kind(Some("employee"), None, Some(own), Some(Uuid::new_v4())).is_err());
        assert!(kind(Some("client"), None, Some(own), None).is_err());
        assert!(kind(Some("overhead"), None, Some(own), None).is_err());
    }

    /// Employee time bills nobody, whatever the request asked for. Enforced
    /// here rather than in the database CHECK, because `is_billable` DEFAULTs
    /// TRUE and an overhead entry logged before migration 119 may carry it.
    #[test]
    fn employee_time_is_never_billable() {
        let own = Uuid::new_v4();
        let resolved = billable_kind(Some(own), Some(own));
        assert_eq!(resolved.kind, "employee");
        assert!(!resolved.billable);
        let resolved = billable_kind(Some(Uuid::new_v4()), Some(own));
        assert!(resolved.billable, "client work keeps what it asked for");
    }

    // PMS-394: work_category derivation.
    #[test]
    fn work_category_derived_from_work_item_when_omitted() {
        let tk = Some(Uuid::new_v4());
        let pr = Some(Uuid::new_v4());
        // No ticket and no project -> general (the ticketless overhead bucket).
        assert_eq!(derive_work_category(None, None, None).unwrap(), "general");
        // A ticket wins over everything.
        assert_eq!(derive_work_category(None, tk, pr).unwrap(), "ticketed");
        // A project with no ticket -> project.
        assert_eq!(derive_work_category(None, None, pr).unwrap(), "project");
        // Blank string is treated as omitted.
        assert_eq!(
            derive_work_category(Some("  "), None, None).unwrap(),
            "general"
        );
    }

    #[test]
    fn work_category_explicit_value_is_honored() {
        let tk = Some(Uuid::new_v4());
        assert_eq!(
            derive_work_category(Some("ticketed"), tk, None).unwrap(),
            "ticketed"
        );
        // Explicit general overrides a present project link.
        assert_eq!(
            derive_work_category(Some("general"), None, Some(Uuid::new_v4())).unwrap(),
            "general"
        );
    }

    #[test]
    fn work_category_ticketed_without_ticket_is_rejected() {
        let err = derive_work_category(Some("ticketed"), None, None).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn work_category_unknown_value_is_rejected() {
        let err = derive_work_category(Some("bogus"), None, None).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }
}
