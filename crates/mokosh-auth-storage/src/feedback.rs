//! Postgres-backed `FeedbackRepository`. Backs the
//! /v1/feedback (public submit) + /v1/admin/feedback (admin triage)
//! surface introduced in `docs/mokosh-fixes/04-feedback-inbox.md`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use mokosh_auth_core::{
    AuthError, Feedback, FeedbackRepository, FeedbackStatus, NewFeedback, TenantId, UserId,
};
use uuid::Uuid;

use crate::conv::db_err;
use crate::pool::AuthPool;

pub struct PgFeedbackRepository {
    pool: AuthPool,
}

impl PgFeedbackRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct FeedbackRow {
    id: Uuid,
    tenant_id: Option<Uuid>,
    submitter_id: Option<Uuid>,
    submitter_name: Option<String>,
    submitter_email: Option<String>,
    subject: Option<String>,
    message: String,
    tags: Vec<String>,
    page_path: Option<String>,
    user_agent: Option<String>,
    ip: Option<IpNetwork>,
    status: String,
    forgejo_issue_url: Option<String>,
    created_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
}

impl TryFrom<FeedbackRow> for Feedback {
    type Error = AuthError;
    fn try_from(r: FeedbackRow) -> Result<Self, Self::Error> {
        Ok(Feedback {
            id: r.id,
            tenant_id: r.tenant_id.map(TenantId),
            submitter_id: r.submitter_id.map(UserId),
            submitter_name: r.submitter_name,
            submitter_email: r.submitter_email,
            subject: r.subject,
            message: r.message,
            tags: r.tags,
            page_path: r.page_path,
            user_agent: r.user_agent,
            ip: r.ip.map(|n| n.ip()),
            status: FeedbackStatus::parse(&r.status).ok_or_else(|| {
                AuthError::Storage(format!("invalid feedback status: {}", r.status))
            })?,
            forgejo_issue_url: r.forgejo_issue_url,
            created_at: r.created_at,
            closed_at: r.closed_at,
        })
    }
}

const SELECT_FEEDBACK: &str = r#"
    SELECT id, tenant_id, submitter_id, submitter_name, submitter_email,
           subject, message, tags, page_path, user_agent, ip, status,
           forgejo_issue_url, created_at, closed_at
    FROM mokosh_auth.feedback
"#;

#[async_trait]
impl FeedbackRepository for PgFeedbackRepository {
    async fn submit(&self, new: NewFeedback) -> Result<Feedback, AuthError> {
        let ip_net: Option<IpNetwork> = new.ip.map(IpNetwork::from);
        let row: FeedbackRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.feedback
                (tenant_id, submitter_id, submitter_name, submitter_email,
                 subject, message, tags, page_path, user_agent, ip)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, tenant_id, submitter_id, submitter_name, submitter_email,
                       subject, message, tags, page_path, user_agent, ip, status,
                       forgejo_issue_url, created_at, closed_at",
        )
        .bind(new.tenant_id.map(|t| t.0))
        .bind(new.submitter_id.map(|u| u.0))
        .bind(new.submitter_name)
        .bind(new.submitter_email)
        .bind(new.subject)
        .bind(&new.message)
        .bind(&new.tags)
        .bind(new.page_path)
        .bind(new.user_agent)
        .bind(ip_net)
        .fetch_one(self.pool.pg())
        .await
        .map_err(db_err)?;
        Feedback::try_from(row)
    }

    async fn list_filtered(
        &self,
        tenant_id: Option<TenantId>,
        status: Option<FeedbackStatus>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Feedback>, u64), AuthError> {
        // tenant_id NULL => global view (every row).
        // tenant_id Some => rows for that tenant PLUS anonymous (null-tenant) rows.
        let tenant_uuid = tenant_id.map(|t| t.0);
        let status_str = status.map(|s| s.as_str());

        let rows: Vec<FeedbackRow> = sqlx::query_as(&format!(
            "{SELECT_FEEDBACK}
             WHERE ($1::uuid IS NULL OR tenant_id IS NULL OR tenant_id = $1)
               AND ($2::text IS NULL OR status = $2)
             ORDER BY created_at DESC
             LIMIT $3 OFFSET $4"
        ))
        .bind(tenant_uuid)
        .bind(status_str)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;

        let (total,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mokosh_auth.feedback
             WHERE ($1::uuid IS NULL OR tenant_id IS NULL OR tenant_id = $1)
               AND ($2::text IS NULL OR status = $2)",
        )
        .bind(tenant_uuid)
        .bind(status_str)
        .fetch_one(self.pool.pg())
        .await
        .map_err(db_err)?;

        let feedback: Result<Vec<_>, _> = rows.into_iter().map(Feedback::try_from).collect();
        Ok((feedback?, total.max(0) as u64))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Feedback>, AuthError> {
        let row: Option<FeedbackRow> = sqlx::query_as(&format!("{SELECT_FEEDBACK} WHERE id = $1"))
            .bind(id)
            .fetch_optional(self.pool.pg())
            .await
            .map_err(db_err)?;
        row.map(Feedback::try_from).transpose()
    }

    async fn set_status(
        &self,
        id: Uuid,
        status: FeedbackStatus,
        actor: UserId,
    ) -> Result<(), AuthError> {
        let (closed_by, closed_at_sql) = match status {
            FeedbackStatus::Closed => (Some(actor.0), "NOW()"),
            _ => (None, "NULL"),
        };
        let sql = format!(
            "UPDATE mokosh_auth.feedback
             SET status = $1, closed_by = $2, closed_at = {closed_at_sql}, updated_at = NOW()
             WHERE id = $3"
        );
        let affected = sqlx::query(&sql)
            .bind(status.as_str())
            .bind(closed_by)
            .bind(id)
            .execute(self.pool.pg())
            .await
            .map_err(db_err)?
            .rows_affected();
        if affected == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }
}
