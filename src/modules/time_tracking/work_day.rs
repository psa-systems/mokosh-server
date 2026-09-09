//! PMS-950: a day of an employee's time, from clock-in to clock-out.
//!
//! The day is the unit, not the work item, and it covers the whole working day
//! rather than only the parts a client pays for. A day is derived from its
//! `work_day_segments` rather than stored: clocking in opens a `work` segment,
//! clocking out closes whichever segment is open, and a break is a `break`
//! segment between two `work` segments, so lunch is "a clock-out" without a
//! second concept. Nothing here creates a time entry: the day view is a reading
//! over the rows `POST /time-entries` and the item timer already write, so an
//! employee's day and a client's invoice are two readings of the same rows.
//!
//! PMS-1145 added the correction half. Until it, the five routes here all
//! acted on *now* - clock in, clock out, break, end break - and a segment,
//! once written, could not be changed by anything: a wrong clock-in time, a
//! clock-out an hour late or a stray segment from a mis-tap was permanent and
//! correctable only with database access. That is a gap against the
//! neighbouring feature, where a `time_entries` row (the thing a customer is
//! billed from) can be edited and deleted through the API.
//!
//! Three things about the correction are decisions rather than mechanics.
//!
//! **Who may do it is a tenant setting** (`timesheets/segment_editing`,
//! [`SegmentEditPolicy`]), the `tickets/note_editing` shape from PMS-974,
//! because it is the same question with the same failure mode: a value
//! outside the closed set read as the default in silence.
//!
//! **The row is edited in place and the change is audited.** `audit_log` is
//! where this codebase's history lives, and a void-and-replace column would
//! be a second home for it - one every existing query would have to learn to
//! skip, the partial unique index on the open segment included.
//!
//! **No day is frozen.** `work_day_segments` is read by this module and
//! nothing else: an invoice bills `time_entries` and a timesheet approves
//! `time_entries`, so a segment correction changes neither, and there is
//! nothing for a freeze to protect. If that stops being true, this is the
//! comment that has to change with it.

use chrono::{DateTime, NaiveDate, Utc};
use uuid::Uuid;

use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::settings::{read_segment_editing, read_track_breaks};
use crate::utils::error::{AppError, AppResult};
use mokosh_types::auth::CurrentUser;
use mokosh_types::datetime::user_today;

use super::models::*;
use super::service::TimeTrackingService;

const SEGMENT_KIND_WORK: &str = "work";
const SEGMENT_KIND_BREAK: &str = "break";

const SEGMENT_COLUMNS: &str = "id, user_id, date, kind, started_at, ended_at";

#[derive(sqlx::FromRow)]
struct SegmentRow {
    id: Uuid,
    user_id: Uuid,
    date: NaiveDate,
    kind: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
}

impl SegmentRow {
    /// Elapsed minutes; an open segment counts up to `now`.
    fn minutes(&self, now: DateTime<Utc>) -> i64 {
        (self.ended_at.unwrap_or(now) - self.started_at)
            .num_minutes()
            .max(0)
    }

    /// The row as an audit payload. Written by hand rather than through
    /// `to_jsonb(t)` so a column added later does not silently start
    /// appearing in the audit history without anyone deciding it should.
    fn audit_value(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "user_id": self.user_id,
            "date": self.date,
            "kind": self.kind,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        })
    }

    fn into_response(self, now: DateTime<Utc>) -> WorkDaySegmentResponse {
        let minutes = self.minutes(now);
        WorkDaySegmentResponse {
            id: self.id,
            user_id: self.user_id,
            date: self.date,
            kind: self.kind,
            started_at: self.started_at,
            ended_at: self.ended_at,
            minutes,
        }
    }
}

/// The person's open segment, whatever its kind or date, locked for the rest
/// of the transaction so two transitions on one clock queue rather than both
/// reading the same open row.
async fn open_segment(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    user_id: Uuid,
) -> AppResult<Option<SegmentRow>> {
    let sql = format!(
        "SELECT {SEGMENT_COLUMNS} FROM work_day_segments \
         WHERE tenant_id = $1 AND user_id = $2 AND ended_at IS NULL \
         FOR UPDATE"
    );
    Ok(sqlx::query_as::<_, SegmentRow>(&sql)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?)
}

async fn close_segment(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    at: DateTime<Utc>,
) -> AppResult<SegmentRow> {
    let sql = format!(
        "UPDATE work_day_segments SET ended_at = $2 WHERE id = $1 RETURNING {SEGMENT_COLUMNS}"
    );
    Ok(sqlx::query_as::<_, SegmentRow>(&sql)
        .bind(id)
        .bind(at)
        .fetch_one(&mut *conn)
        .await?)
}

/// Open a segment. The partial unique index on the open segment per user is
/// what closes the race between two clock-ins that both saw nothing open, the
/// way `active_timers.UNIQUE(user_id)` does for the item timer; it surfaces as
/// the same 409 the pre-check gives.
async fn open_new_segment(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    user_id: Uuid,
    date: NaiveDate,
    kind: &str,
    at: DateTime<Utc>,
) -> AppResult<SegmentRow> {
    let sql = format!(
        "INSERT INTO work_day_segments (id, tenant_id, user_id, date, kind, started_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {SEGMENT_COLUMNS}"
    );
    match sqlx::query_as::<_, SegmentRow>(&sql)
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(user_id)
        .bind(date)
        .bind(kind)
        .bind(at)
        .fetch_one(&mut *conn)
        .await
    {
        Ok(row) => Ok(row),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(AppError::Conflict(
            "Already clocked in; clock out first".to_string(),
        )),
        Err(e) => Err(e.into()),
    }
}

/// Break tracking is a tenant setting (PMS-943), off until an employer says
/// otherwise. With it off the break routes answer the way the module gate
/// does, 404, so a disabled control reads like a route that does not exist.
async fn require_break_tracking(
    service: &TimeTrackingService,
    tenant_id: TenantId,
) -> AppResult<()> {
    if read_track_breaks(&service.db, tenant_id).await? {
        Ok(())
    } else {
        Err(AppError::NotFound("Break tracking".to_string()))
    }
}

/// One grouped row of the day's `time_entries`. Grouped in SQL by what an
/// entry is attached to, bucketed in Rust.
#[derive(sqlx::FromRow)]
struct BreakdownRow {
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    entry_kind: String,
    ticket_number: Option<String>,
    ticket_title: Option<String>,
    project_name: Option<String>,
    minutes: i64,
    entry_count: i64,
}

/// Which of the four parts an entry belongs to. Ticket first, then project,
/// because an entry may name both (a task on a project's ticket) and the
/// ticket is the finer reading. Then the MSP's own time (`entry_kind =
/// 'employee'`, PMS-942, which by the migration 119 CHECK names neither), and
/// whatever is left is client work with no work item, which PMS-942 says is
/// the client's time and so must not be filed under Administrative.
fn bucket(rows: Vec<BreakdownRow>) -> WorkDayBreakdown {
    let mut breakdown = WorkDayBreakdown::default();
    for row in rows {
        if let Some(ticket_id) = row.ticket_id {
            match breakdown
                .tickets
                .iter_mut()
                .find(|line| line.ticket_id == ticket_id)
            {
                Some(line) => {
                    line.minutes += row.minutes;
                    line.entry_count += row.entry_count;
                }
                None => breakdown.tickets.push(WorkDayTicketLine {
                    ticket_id,
                    ticket_number: row.ticket_number,
                    ticket_title: row.ticket_title,
                    minutes: row.minutes,
                    entry_count: row.entry_count,
                }),
            }
        } else if let Some(project_id) = row.project_id {
            match breakdown
                .projects
                .iter_mut()
                .find(|line| line.project_id == project_id)
            {
                Some(line) => {
                    line.minutes += row.minutes;
                    line.entry_count += row.entry_count;
                }
                None => breakdown.projects.push(WorkDayProjectLine {
                    project_id,
                    project_name: row.project_name,
                    minutes: row.minutes,
                    entry_count: row.entry_count,
                }),
            }
        } else if row.entry_kind == "employee" {
            breakdown.administrative.minutes += row.minutes;
            breakdown.administrative.entry_count += row.entry_count;
        } else {
            breakdown.unattached.minutes += row.minutes;
            breakdown.unattached.entry_count += row.entry_count;
        }
    }
    // Largest share first, and a stable order under it so two reads of one
    // day agree.
    breakdown.tickets.sort_by(|a, b| {
        b.minutes
            .cmp(&a.minutes)
            .then(a.ticket_id.cmp(&b.ticket_id))
    });
    breakdown.projects.sort_by(|a, b| {
        b.minutes
            .cmp(&a.minutes)
            .then(a.project_id.cmp(&b.project_id))
    });
    breakdown
}

impl TimeTrackingService {
    /// Clock in: open a `work` segment on `request.date` (the client's day),
    /// or on today in the user's own zone (`users.timezone`, the preference
    /// the dashboard's "today" already follows, PMS-253). Refused while any
    /// segment is open, whatever its date, because a day that was never
    /// clocked out is still that day.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn clock_in(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        user_tz: &str,
        request: &ClockInRequest,
    ) -> AppResult<WorkDaySegmentResponse> {
        let now = Utc::now();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        if let Some(open) = open_segment(&mut tx, tenant_id, user_id).await? {
            let message = if open.kind == SEGMENT_KIND_BREAK {
                "Already clocked in and on a break; end the break or clock out first"
            } else {
                "Already clocked in; clock out first"
            };
            return Err(AppError::Conflict(message.to_string()));
        }
        let date = request.date.unwrap_or_else(|| user_today(now, user_tz));
        let segment =
            open_new_segment(&mut tx, tenant_id, user_id, date, SEGMENT_KIND_WORK, now).await?;
        tx.commit().await?;
        Ok(segment.into_response(now))
    }

    /// PMS-1145: correct a recorded segment.
    ///
    /// The policy decides WHO (see [`SegmentEditPolicy`]); this decides what
    /// a correction may leave behind. Three refusals, and each is a state the
    /// table's own constraints would otherwise reject with a message naming a
    /// constraint rather than the problem:
    ///
    /// - an end before its start (the `CHECK` on the table),
    /// - a second open segment for the person, which is what reopening a
    ///   closed one can produce (the partial unique index), and
    /// - a segment that is still open being given a start in the future,
    ///   which would read as negative elapsed time on the day view.
    ///
    /// The day is not recomputed anywhere, because there is nothing to
    /// recompute: PMS-950 derives every total from the segments on each read,
    /// which is the property that makes this operation safe at all.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, segment_id = %segment_id))]
    pub async fn update_segment(
        &self,
        tenant_id: TenantId,
        caller: &CurrentUser,
        ctx: &AuditCtx,
        segment_id: Uuid,
        request: &UpdateWorkDaySegmentRequest,
    ) -> AppResult<WorkDaySegmentResponse> {
        let policy = self.segment_edit_policy(tenant_id).await?;
        let now = Utc::now();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Locked for the rest of the transaction: two corrections to one
        // segment, or a correction racing a clock-out, must queue rather than
        // both read the same row.
        let sql = format!(
            "SELECT {SEGMENT_COLUMNS} FROM work_day_segments \
             WHERE tenant_id = $1 AND id = $2 FOR UPDATE"
        );
        let before: Option<SegmentRow> = sqlx::query_as(&sql)
            .bind(tenant_id)
            .bind(segment_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(before) = before else {
            return Err(AppError::NotFound("Work day segment".to_string()));
        };
        if !policy.permits(caller, before.user_id) {
            // 403 and not 404: the segment exists and the caller may well be
            // able to READ the day it belongs to, so pretending it is absent
            // would be a lie they can immediately disprove.
            return Err(AppError::Forbidden(
                "Not allowed to correct this work day segment".to_string(),
            ));
        }

        let date = request.date.unwrap_or(before.date);
        let started_at = request.started_at.unwrap_or(before.started_at);
        // Absent leaves the end alone; an explicit null reopens the segment.
        let ended_at = match request.ended_at {
            None => before.ended_at,
            Some(value) => value,
        };

        if let Some(end) = ended_at {
            if end < started_at {
                return Err(AppError::BadRequest(
                    "A segment cannot end before it starts".to_string(),
                ));
            }
        } else {
            if started_at > now {
                return Err(AppError::BadRequest(
                    "An open segment cannot start in the future".to_string(),
                ));
            }
            // Reopening while something else is open is the one refusal a
            // caller can hit without doing anything obviously wrong, so it
            // says which segment is in the way.
            if let Some(open) = open_segment(&mut tx, tenant_id, before.user_id).await? {
                if open.id != segment_id {
                    return Err(AppError::Conflict(
                        "This person already has an open segment; close it before reopening this one"
                            .to_string(),
                    ));
                }
            }
        }

        let sql = format!(
            "UPDATE work_day_segments SET date = $3, started_at = $4, ended_at = $5 \
             WHERE tenant_id = $1 AND id = $2 RETURNING {SEGMENT_COLUMNS}"
        );
        let after: SegmentRow = sqlx::query_as(&sql)
            .bind(tenant_id)
            .bind(segment_id)
            .bind(date)
            .bind(started_at)
            .bind(ended_at)
            .fetch_one(&mut *tx)
            .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "work_day_segments",
            Some(segment_id),
            Some(before.audit_value()),
            Some(after.audit_value()),
        )
        .await?;
        tx.commit().await?;
        Ok(after.into_response(now))
    }

    /// PMS-1145: remove a recorded segment.
    ///
    /// A delete rather than a flag, for the reason the module docs give: the
    /// day is derived from its segments on every read, so removing one is
    /// complete by construction, and `audit_log` holds what it was. Deleting
    /// the OPEN segment is allowed and is how a mis-tapped clock-in is undone
    /// - it leaves the person clocked out, which is what they were.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, segment_id = %segment_id))]
    pub async fn delete_segment(
        &self,
        tenant_id: TenantId,
        caller: &CurrentUser,
        ctx: &AuditCtx,
        segment_id: Uuid,
    ) -> AppResult<()> {
        let policy = self.segment_edit_policy(tenant_id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let sql = format!(
            "SELECT {SEGMENT_COLUMNS} FROM work_day_segments \
             WHERE tenant_id = $1 AND id = $2 FOR UPDATE"
        );
        let before: Option<SegmentRow> = sqlx::query_as(&sql)
            .bind(tenant_id)
            .bind(segment_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(before) = before else {
            return Err(AppError::NotFound("Work day segment".to_string()));
        };
        if !policy.permits(caller, before.user_id) {
            return Err(AppError::Forbidden(
                "Not allowed to correct this work day segment".to_string(),
            ));
        }

        sqlx::query("DELETE FROM work_day_segments WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(segment_id)
            .execute(&mut *tx)
            .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "work_day_segments",
            Some(segment_id),
            Some(before.audit_value()),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The tenant's correction policy, or the default when it is unset or
    /// holds a value the closed set does not contain. A row outside the set
    /// cannot be written through `PUT /settings`, which validates it, but can
    /// exist from a hand-written row - and reading it as the default is the
    /// same fallback `NoteEditPolicy` takes for the same reason.
    async fn segment_edit_policy(&self, tenant_id: TenantId) -> AppResult<SegmentEditPolicy> {
        Ok(read_segment_editing(&self.db, tenant_id)
            .await?
            .and_then(|stored| SegmentEditPolicy::parse(&stored))
            .unwrap_or_default())
    }

    /// Clock out: close whichever segment is open. A day may end on a break,
    /// because the person went home from lunch.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn clock_out(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> AppResult<WorkDaySegmentResponse> {
        let now = Utc::now();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let Some(open) = open_segment(&mut tx, tenant_id, user_id).await? else {
            return Err(AppError::Conflict("Not clocked in".to_string()));
        };
        let closed = close_segment(&mut tx, open.id, now).await?;
        tx.commit().await?;
        Ok(closed.into_response(now))
    }

    /// Start a break: close the open `work` segment and open a `break` one at
    /// the same instant, in one transaction, so the day has no gap and no
    /// overlap between the two.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn start_break(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> AppResult<WorkDaySegmentResponse> {
        require_break_tracking(self, tenant_id).await?;
        let now = Utc::now();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let Some(open) = open_segment(&mut tx, tenant_id, user_id).await? else {
            return Err(AppError::Conflict(
                "Not clocked in; clock in first".to_string(),
            ));
        };
        if open.kind == SEGMENT_KIND_BREAK {
            return Err(AppError::Conflict("Already on a break".to_string()));
        }
        close_segment(&mut tx, open.id, now).await?;
        let segment = open_new_segment(
            &mut tx,
            tenant_id,
            user_id,
            open.date,
            SEGMENT_KIND_BREAK,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(segment.into_response(now))
    }

    /// End a break: close the open `break` segment and reopen `work` on the
    /// same day at the same instant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn end_break(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> AppResult<WorkDaySegmentResponse> {
        require_break_tracking(self, tenant_id).await?;
        let now = Utc::now();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let open = match open_segment(&mut tx, tenant_id, user_id).await? {
            Some(open) if open.kind == SEGMENT_KIND_BREAK => open,
            _ => return Err(AppError::Conflict("Not on a break".to_string())),
        };
        close_segment(&mut tx, open.id, now).await?;
        let segment = open_new_segment(
            &mut tx,
            tenant_id,
            user_id,
            open.date,
            SEGMENT_KIND_WORK,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(segment.into_response(now))
    }

    /// The day view: the day's segments and its time entries, read together.
    /// No `date` means the day of the open segment if there is one, else
    /// today in the user's own zone, so a reload finds the clock where it was
    /// left.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn work_day(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        user_tz: &str,
        date: Option<NaiveDate>,
    ) -> AppResult<WorkDayResponse> {
        let track_breaks = read_track_breaks(&self.db, tenant_id).await?;
        let now = Utc::now();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        let date = match date {
            Some(date) => date,
            None => sqlx::query_scalar::<_, NaiveDate>(
                "SELECT date FROM work_day_segments \
                 WHERE tenant_id = $1 AND user_id = $2 AND ended_at IS NULL",
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or_else(|| user_today(now, user_tz)),
        };

        let sql = format!(
            "SELECT {SEGMENT_COLUMNS} FROM work_day_segments \
             WHERE tenant_id = $1 AND user_id = $2 AND date = $3 \
             ORDER BY started_at"
        );
        let segments: Vec<SegmentRow> = sqlx::query_as(&sql)
            .bind(tenant_id)
            .bind(user_id)
            .bind(date)
            .fetch_all(&mut *tx)
            .await?;

        // `worked_minutes` is the actual time (PMS-395) and is NULL only on
        // rows older than migration 081, which carried it in `duration_minutes`.
        let rows: Vec<BreakdownRow> = sqlx::query_as(
            r#"
            SELECT te.ticket_id, te.project_id, te.entry_kind,
                   tk.ticket_number, tk.title AS ticket_title, pr.name AS project_name,
                   COALESCE(SUM(COALESCE(te.worked_minutes, te.duration_minutes)), 0)::BIGINT AS minutes,
                   COUNT(*)::BIGINT AS entry_count
            FROM time_entries te
            LEFT JOIN tickets  tk ON tk.id = te.ticket_id
            LEFT JOIN projects pr ON pr.id = te.project_id
            WHERE te.tenant_id = $1 AND te.user_id = $2 AND te.date = $3
            GROUP BY te.ticket_id, te.project_id, te.entry_kind,
                     tk.ticket_number, tk.title, pr.name
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(date)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let open = segments.iter().find(|s| s.ended_at.is_none());
        let is_clocked_in = open.is_some();
        let on_break = open.is_some_and(|s| s.kind == SEGMENT_KIND_BREAK);
        let clocked_minutes = segments
            .iter()
            .filter(|s| s.kind == SEGMENT_KIND_WORK)
            .map(|s| s.minutes(now))
            .sum();
        let break_minutes = segments
            .iter()
            .filter(|s| s.kind == SEGMENT_KIND_BREAK)
            .map(|s| s.minutes(now))
            .sum();
        let logged_minutes: i64 = rows.iter().map(|r| r.minutes).sum();

        Ok(WorkDayResponse {
            user_id,
            date,
            is_clocked_in,
            on_break,
            track_breaks,
            segments: segments.into_iter().map(|s| s.into_response(now)).collect(),
            clocked_minutes,
            break_minutes,
            logged_minutes,
            unlogged_minutes: clocked_minutes - logged_minutes,
            breakdown: bucket(rows),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        ticket_id: Option<Uuid>,
        project_id: Option<Uuid>,
        entry_kind: &str,
        minutes: i64,
    ) -> BreakdownRow {
        BreakdownRow {
            ticket_id,
            project_id,
            entry_kind: entry_kind.to_string(),
            ticket_number: ticket_id.map(|_| "T-1".to_string()),
            ticket_title: ticket_id.map(|_| "Printer".to_string()),
            project_name: project_id.map(|_| "Rollout".to_string()),
            minutes,
            entry_count: 1,
        }
    }

    /// The four parts partition the day: every minute lands in exactly one,
    /// and a ticket named twice (with and without a project) is one line.
    #[test]
    fn the_breakdown_partitions_the_day() {
        let ticket = Uuid::new_v4();
        let project = Uuid::new_v4();
        let breakdown = bucket(vec![
            row(Some(ticket), None, "client", 30),
            row(Some(ticket), Some(project), "client", 15),
            row(None, Some(project), "client", 60),
            row(None, None, "employee", 45),
            row(None, None, "client", 20),
        ]);
        assert_eq!(breakdown.tickets.len(), 1);
        assert_eq!(breakdown.tickets[0].minutes, 45);
        assert_eq!(breakdown.tickets[0].entry_count, 2);
        assert_eq!(breakdown.projects.len(), 1);
        assert_eq!(breakdown.projects[0].minutes, 60);
        assert_eq!(breakdown.administrative.minutes, 45);
        assert_eq!(breakdown.unattached.minutes, 20);
        let total = breakdown.tickets[0].minutes
            + breakdown.projects[0].minutes
            + breakdown.administrative.minutes
            + breakdown.unattached.minutes;
        assert_eq!(total, 170);
    }

    /// An open segment counts up to now; a closed one is fixed.
    #[test]
    fn an_open_segment_counts_to_now() {
        let now = Utc::now();
        let started_at = now - chrono::Duration::minutes(90);
        let open = SegmentRow {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            date: now.date_naive(),
            kind: SEGMENT_KIND_WORK.to_string(),
            started_at,
            ended_at: None,
        };
        assert_eq!(open.minutes(now), 90);
        let closed = SegmentRow {
            ended_at: Some(started_at + chrono::Duration::minutes(30)),
            ..open
        };
        assert_eq!(closed.minutes(now), 30);
    }
}
