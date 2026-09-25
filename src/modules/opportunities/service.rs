//! Store and business logic for opportunities.

use chrono::Utc;
use rust_decimal::Decimal;
use sqlx::Row;
use uuid::Uuid;

use super::models::{
    is_closed_stage, CloseOpportunityRequest, CreateOpportunityRequest, Opportunity,
    UpdateOpportunityRequest, OUTCOMES, STAGES,
};
use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

/// Read-side filters accepted by `list`. All optional.
#[derive(Debug, Default, Clone)]
pub struct OpportunityFilter {
    pub company_id: Option<Uuid>,
    pub stage: Option<String>,
    /// `Some(true)` returns only closed opportunities, `Some(false)`
    /// only open ones, `None` returns both.
    pub closed: Option<bool>,
}

#[derive(Clone)]
pub struct OpportunitiesService {
    db: Database,
}

impl OpportunitiesService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    fn ensure_stage(stage: &str) -> AppResult<()> {
        if !STAGES.contains(&stage) {
            return Err(AppError::validation_field(
                "stage",
                format!("unknown stage `{stage}`; accepted: {}", STAGES.join(", ")),
            ));
        }
        Ok(())
    }

    fn ensure_outcome(outcome: &str) -> AppResult<()> {
        if !OUTCOMES.contains(&outcome) {
            return Err(AppError::validation_field(
                "outcome",
                format!(
                    "unknown outcome `{outcome}`; accepted: {}",
                    OUTCOMES.join(", ")
                ),
            ));
        }
        Ok(())
    }

    /// Refuse a foreign company id up front so the FK is a backstop
    /// rather than the first defence. Returns the row's tenant_id for
    /// the caller to compare with expectations.
    async fn assert_company_in_tenant(
        &self,
        tx: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        company_id: Uuid,
    ) -> AppResult<()> {
        let found: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM companies WHERE tenant_id = $1 AND id = $2")
                .bind(*tenant_id)
                .bind(company_id)
                .fetch_optional(&mut *tx)
                .await?;
        if found.is_none() {
            return Err(AppError::validation_field(
                "company_id",
                "company does not exist in this tenant",
            ));
        }
        Ok(())
    }

    pub async fn create(
        &self,
        tenant_id: TenantId,
        created_by_id: Uuid,
        request: &CreateOpportunityRequest,
    ) -> AppResult<Opportunity> {
        let stage = request.stage.as_deref().unwrap_or("lead");
        Self::ensure_stage(stage)?;
        if is_closed_stage(stage) {
            return Err(AppError::validation_field(
                "stage",
                "an opportunity is created open; close it through the close endpoint",
            ));
        }
        let currency = request
            .currency
            .as_deref()
            .unwrap_or("USD")
            .to_ascii_uppercase();
        if currency.len() != 3 {
            return Err(AppError::validation_field(
                "currency",
                "currency must be a 3-letter ISO 4217 code",
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        self.assert_company_in_tenant(&mut tx, tenant_id, request.company_id)
            .await?;
        if let Some(cid) = request.contact_id {
            let found: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM contacts WHERE tenant_id = $1 AND id = $2")
                    .bind(*tenant_id)
                    .bind(cid)
                    .fetch_optional(&mut *tx)
                    .await?;
            if found.is_none() {
                return Err(AppError::validation_field(
                    "contact_id",
                    "contact does not exist in this tenant",
                ));
            }
        }

        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO opportunities ( \
                 id, tenant_id, company_id, contact_id, title, value_amount, \
                 currency, stage, expected_close_date, notes, created_by_id \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(id)
        .bind(*tenant_id)
        .bind(request.company_id)
        .bind(request.contact_id)
        .bind(&request.title)
        .bind(request.value_amount)
        .bind(&currency)
        .bind(stage)
        .bind(request.expected_close_date)
        .bind(request.notes.as_deref())
        .bind(created_by_id)
        .execute(&mut *tx)
        .await?;

        let row = self.load_row(&mut tx, id).await?;
        tx.commit().await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: TenantId, id: Uuid) -> AppResult<Opportunity> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        self.load_row(&mut tx, id).await
    }

    pub async fn list(
        &self,
        tenant_id: TenantId,
        filter: &OpportunityFilter,
    ) -> AppResult<Vec<Opportunity>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Assemble the WHERE clause once. `stage` and `company_id` are
        // bound; `closed` maps onto `closed_at IS [NOT] NULL`.
        let mut sql =
            String::from("SELECT * FROM opportunities WHERE tenant_id = $1 AND deleted_at IS NULL");
        let mut idx: usize = 2;
        if filter.company_id.is_some() {
            sql.push_str(&format!(" AND company_id = ${idx}"));
            idx += 1;
        }
        if filter.stage.is_some() {
            sql.push_str(&format!(" AND stage = ${idx}"));
            idx += 1;
        }
        if let Some(closed) = filter.closed {
            if closed {
                sql.push_str(" AND closed_at IS NOT NULL");
            } else {
                sql.push_str(" AND closed_at IS NULL");
            }
        }
        sql.push_str(" ORDER BY updated_at DESC");
        let _ = idx;

        let mut q = sqlx::query(&sql).bind(*tenant_id);
        if let Some(cid) = filter.company_id {
            q = q.bind(cid);
        }
        if let Some(stage) = filter.stage.as_deref() {
            Self::ensure_stage(stage)?;
            q = q.bind(stage);
        }
        let rows = q.fetch_all(&mut *tx).await?;
        Ok(rows.into_iter().map(row_to_opportunity).collect())
    }

    pub async fn update(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpdateOpportunityRequest,
    ) -> AppResult<Opportunity> {
        if let Some(stage) = request.stage.as_deref() {
            Self::ensure_stage(stage)?;
            if is_closed_stage(stage) {
                return Err(AppError::validation_field(
                    "stage",
                    "close an opportunity through the close endpoint rather than the update path",
                ));
            }
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing = self.load_row(&mut tx, id).await?;
        if existing.closed_at.is_some() {
            return Err(AppError::BadRequest(
                "a closed opportunity is immutable; open a new one to record follow-up work".into(),
            ));
        }

        if let Some(cid) = request.quote_id.and_then(|c| c) {
            let found: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM quotes WHERE tenant_id = $1 AND id = $2")
                    .bind(*tenant_id)
                    .bind(cid)
                    .fetch_optional(&mut *tx)
                    .await?;
            if found.is_none() {
                return Err(AppError::validation_field(
                    "quote_id",
                    "quote does not exist in this tenant",
                ));
            }
        }

        // Build a dynamic UPDATE from the fields the caller named. The
        // schema-level CHECKs stay the ultimate guard.
        let mut sql = String::from("UPDATE opportunities SET updated_at = NOW()");
        let mut idx: usize = 3;
        macro_rules! push {
            ($field:literal, $cond:expr) => {
                if $cond {
                    sql.push_str(&format!(", {} = ${}", $field, idx));
                    idx += 1;
                }
            };
        }
        push!("contact_id", request.contact_id.is_some());
        push!("title", request.title.is_some());
        push!("value_amount", request.value_amount.is_some());
        push!("currency", request.currency.is_some());
        push!("stage", request.stage.is_some());
        push!("expected_close_date", request.expected_close_date.is_some());
        push!("quote_id", request.quote_id.is_some());
        push!("notes", request.notes.is_some());
        sql.push_str(" WHERE tenant_id = $1 AND id = $2");
        let _ = idx;

        let mut q = sqlx::query(&sql).bind(*tenant_id).bind(id);
        if let Some(v) = request.contact_id {
            q = q.bind(v);
        }
        if let Some(v) = request.title.as_deref() {
            q = q.bind(v);
        }
        if let Some(v) = request.value_amount {
            q = q.bind(v);
        }
        if let Some(v) = request.currency.as_deref() {
            let upper = v.to_ascii_uppercase();
            if upper.len() != 3 {
                return Err(AppError::validation_field(
                    "currency",
                    "currency must be a 3-letter ISO 4217 code",
                ));
            }
            q = q.bind(upper);
        }
        if let Some(v) = request.stage.as_deref() {
            q = q.bind(v.to_string());
        }
        if let Some(v) = request.expected_close_date {
            q = q.bind(v);
        }
        if let Some(v) = request.quote_id {
            q = q.bind(v);
        }
        if let Some(v) = request.notes.as_ref() {
            q = q.bind(v.as_deref());
        }
        q.execute(&mut *tx).await?;

        let row = self.load_row(&mut tx, id).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Close a previously-open opportunity. Sets stage, outcome and
    /// closed_at in one write, and (on `won`) accepts an optional
    /// `quote_id` link to the quote that closed the sale.
    pub async fn close(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &CloseOpportunityRequest,
    ) -> AppResult<Opportunity> {
        Self::ensure_outcome(&request.outcome)?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing = self.load_row(&mut tx, id).await?;
        if existing.closed_at.is_some() {
            return Err(AppError::BadRequest("opportunity is already closed".into()));
        }

        let effective_quote = if request.outcome == "won" {
            if let Some(qid) = request.quote_id {
                let found: Option<Uuid> =
                    sqlx::query_scalar("SELECT id FROM quotes WHERE tenant_id = $1 AND id = $2")
                        .bind(*tenant_id)
                        .bind(qid)
                        .fetch_optional(&mut *tx)
                        .await?;
                if found.is_none() {
                    return Err(AppError::validation_field(
                        "quote_id",
                        "quote does not exist in this tenant",
                    ));
                }
                Some(qid)
            } else {
                existing.quote_id
            }
        } else {
            existing.quote_id
        };

        sqlx::query(
            "UPDATE opportunities \
             SET stage = $3, outcome = $3, quote_id = $4, closed_at = $5, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(*tenant_id)
        .bind(id)
        .bind(&request.outcome)
        .bind(effective_quote)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await?;

        let row = self.load_row(&mut tx, id).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Soft-delete: the row keeps its history so a reporting query
    /// hitting it after the fact still sees the outcome. Reads exclude
    /// soft-deleted rows already.
    pub async fn soft_delete(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let result = sqlx::query(
            "UPDATE opportunities SET deleted_at = NOW(), updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
        )
        .bind(*tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Opportunity".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    async fn load_row(&self, tx: &mut sqlx::PgConnection, id: Uuid) -> AppResult<Opportunity> {
        let row = sqlx::query("SELECT * FROM opportunities WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Opportunity".to_string()))?;
        Ok(row_to_opportunity(row))
    }
}

fn row_to_opportunity(row: sqlx::postgres::PgRow) -> Opportunity {
    Opportunity {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        company_id: row.get("company_id"),
        contact_id: row.get("contact_id"),
        title: row.get("title"),
        value_amount: row.get::<Option<Decimal>, _>("value_amount"),
        currency: row.get("currency"),
        stage: row.get("stage"),
        expected_close_date: row.get("expected_close_date"),
        outcome: row.get("outcome"),
        quote_id: row.get("quote_id"),
        notes: row.get("notes"),
        created_by_id: row.get("created_by_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        closed_at: row.get("closed_at"),
    }
}
