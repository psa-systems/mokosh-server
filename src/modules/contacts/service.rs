//! Contact service implementation

use std::sync::Arc;

use crate::modules::auth::TenantId;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::utils::crypto::{generate_token, hash_password};
use crate::utils::email::{LogMailer, Mailer};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// How long a portal setup link remains redeemable. Mirrors the
/// password-reset redemption window (PMS-136).
const PORTAL_SETUP_TOKEN_TTL_HOURS: i64 = 72;

/// Contact management service
#[derive(Clone)]
pub struct ContactService {
    db: Database,
    /// Outbound mailer used to deliver portal setup-link emails. Defaults
    /// to `LogMailer` (dev/tests log the link) unless the router wires the
    /// shared `Mailer`.
    mailer: Arc<dyn Mailer>,
    /// Base URL of the customer-facing SPA. The setup link is
    /// `{app_url}/portal/set-password?token=...`.
    app_url: String,
}

impl ContactService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            mailer: Arc::new(LogMailer),
            app_url: String::new(),
        }
    }

    /// Construct with the shared mailer and SPA base URL so granting
    /// portal access can email the contact a setup link (PMS-136).
    pub fn with_mailer(db: Database, mailer: Arc<dyn Mailer>, app_url: String) -> Self {
        Self {
            db,
            mailer,
            app_url,
        }
    }

    /// Reject a foreign id that does not belong to this tenant, so a request
    /// body cannot link a row to another tenant's data. `table` is a
    /// compile-time constant, never user input.
    async fn validate_fk(
        &self,
        tenant_id: TenantId,
        table: &'static str,
        id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE tenant_id = $1 AND id = $2)"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            Ok(())
        } else {
            Err(AppError::BadRequest(format!(
                "Referenced {table} not found in this tenant"
            )))
        }
    }

    async fn validate_fk_opt(
        &self,
        tenant_id: TenantId,
        table: &'static str,
        id: Option<Uuid>,
    ) -> AppResult<()> {
        match id {
            Some(id) => self.validate_fk(tenant_id, table, id).await,
            None => Ok(()),
        }
    }

    // ========================================================================
    // COMPANIES
    // ========================================================================

    /// Create a new company
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_company(
        &self,
        tenant_id: TenantId,
        request: &CreateCompanyRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Company> {
        let company_id = Uuid::new_v4();
        let address = request.address.clone().unwrap_or_default();
        let billing_address = request.billing_address.clone().unwrap_or_default();

        // PSA audit: every foreign id from the request body must belong to
        // this tenant before it is linked.
        self.validate_fk_opt(tenant_id, "companies", request.parent_company_id)
            .await?;
        self.validate_fk_opt(tenant_id, "users", request.account_manager_id)
            .await?;
        self.validate_fk_opt(tenant_id, "sla_policies", request.sla_id)
            .await?;

        // Mutation + audit row in one transaction so a rollback drops
        // both. CREATE: old = None, after captured by the new row id.
        // PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO companies (
                id, tenant_id, name, parent_company_id, company_type, status,
                industry, website, phone, fax,
                address_line1, address_line2, city, state, postal_code, country,
                billing_address_line1, billing_address_line2, billing_city,
                billing_state, billing_postal_code, billing_country,
                tax_id, account_number, account_manager_id, sla_id,
                payment_terms, tax_exempt, custom_fields, tags, notes, portal_enabled
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
                $23, $24, $25, $26, $27, $28, $29, $30, $31, $32
            )
            "#,
        )
        .bind(company_id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(request.parent_company_id)
        .bind(request.company_type.as_str())
        .bind(request.status.as_str())
        .bind(&request.industry)
        .bind(&request.website)
        .bind(&request.phone)
        .bind(&request.fax)
        .bind(&address.line1)
        .bind(&address.line2)
        .bind(&address.city)
        .bind(&address.state)
        .bind(&address.postal_code)
        .bind(&address.country)
        .bind(&billing_address.line1)
        .bind(&billing_address.line2)
        .bind(&billing_address.city)
        .bind(&billing_address.state)
        .bind(&billing_address.postal_code)
        .bind(&billing_address.country)
        .bind(&request.tax_id)
        .bind(&request.account_number)
        .bind(request.account_manager_id)
        .bind(request.sla_id)
        .bind(&request.payment_terms)
        .bind(request.tax_exempt)
        .bind(&request.custom_fields)
        .bind(&request.tags)
        .bind(&request.notes)
        .bind(request.portal_enabled)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM companies c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "companies",
            Some(company_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_company(tenant_id, company_id).await
    }

    /// Get company by ID
    /// Populate the optional rollup fields on a `CompanyResponse`
    /// (`account_manager_name`, `contact_count`, `site_count`,
    /// `open_ticket_count`). The base list / get queries are kept on
    /// the lean `Company` shape so internal callers that only need the
    /// row keep working; this method runs ONE follow-up query per page
    /// of results, regardless of page size, to fill in the counts the
    /// list page renders.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn enrich_companies(
        &self,
        tenant_id: TenantId,
        mut responses: Vec<CompanyResponse>,
    ) -> AppResult<Vec<CompanyResponse>> {
        if responses.is_empty() {
            return Ok(responses);
        }
        let ids: Vec<Uuid> = responses.iter().map(|r| r.id).collect();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, CompanyRollupRow>(
            r#"
            SELECT
                c.id AS company_id,
                CASE
                    WHEN u.id IS NULL THEN NULL
                    ELSE u.first_name || ' ' || u.last_name
                END AS account_manager_name,
                (SELECT COUNT(*) FROM contacts ct
                    WHERE ct.tenant_id = c.tenant_id
                      AND ct.company_id = c.id) AS contact_count,
                (SELECT COUNT(*) FROM sites s
                    WHERE s.tenant_id = c.tenant_id
                      AND s.company_id = c.id) AS site_count,
                (SELECT COUNT(*) FROM tickets t
                    WHERE t.tenant_id = c.tenant_id
                      AND t.company_id = c.id
                      AND t.closed_at IS NULL) AS open_ticket_count
            FROM companies c
            LEFT JOIN users u ON u.id = c.account_manager_id
            WHERE c.tenant_id = $1
              AND c.id = ANY($2)
            "#,
        )
        .bind(tenant_id)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
        let mut by_id: std::collections::HashMap<Uuid, CompanyRollupRow> =
            rows.into_iter().map(|r| (r.company_id, r)).collect();
        for resp in responses.iter_mut() {
            if let Some(row) = by_id.remove(&resp.id) {
                resp.account_manager_name = row.account_manager_name;
                resp.contact_count = Some(row.contact_count);
                resp.site_count = Some(row.site_count);
                resp.open_ticket_count = Some(row.open_ticket_count);
            }
        }
        Ok(responses)
    }

    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_company(&self, tenant_id: TenantId, company_id: Uuid) -> AppResult<Company> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, CompanyRow>(
            r#"
            SELECT id, tenant_id, name, parent_company_id, company_type, status,
                   industry, website, phone, fax,
                   address_line1, address_line2, city, state, postal_code, country,
                   billing_address_line1, billing_address_line2, billing_city,
                   billing_state, billing_postal_code, billing_country,
                   tax_id, account_number, default_billing_contact_id,
                   default_technical_contact_id, account_manager_id, sla_id,
                   default_contract_id, payment_terms, tax_exempt,
                   custom_fields, tags, notes, logo_url, portal_enabled,
                   created_at, updated_at
            FROM companies
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Company".to_string()))?;

        Ok(row.into())
    }

    /// List companies with filters
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_companies(
        &self,
        tenant_id: TenantId,
        filter: &CompanyFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Company>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        // Parallel WHERE clauses so the data and count queries each get
        // correctly numbered placeholders. data has $1 tenant + $2 limit
        // + $3 offset → filter binds at $4+; count has $1 tenant only →
        // filter binds at $2+. Sharing one WHERE string between them
        // misaligns the count_query bind sequence and trips postgres
        // 42P18 ("could not determine data type of parameter").
        let mut data_conds = vec!["tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;

        if filter.q.is_some() {
            data_conds.push(format!("name ILIKE ${data_idx}"));
            count_conds.push(format!("name ILIKE ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.company_type.is_some() {
            data_conds.push(format!("company_type = ${data_idx}"));
            count_conds.push(format!("company_type = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.status.is_some() {
            data_conds.push(format!("status = ${data_idx}"));
            count_conds.push(format!("status = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.account_manager_id.is_some() {
            data_conds.push(format!("account_manager_id = ${data_idx}"));
            count_conds.push(format!("account_manager_id = ${count_idx}"));
        }

        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        let order_by = pagination.order_by("name", &["name", "created_at", "updated_at"]);

        let query = format!(
            r#"
            SELECT id, tenant_id, name, parent_company_id, company_type, status,
                   industry, website, phone, fax,
                   address_line1, address_line2, city, state, postal_code, country,
                   billing_address_line1, billing_address_line2, billing_city,
                   billing_state, billing_postal_code, billing_country,
                   tax_id, account_number, default_billing_contact_id,
                   default_technical_contact_id, account_manager_id, sla_id,
                   default_contract_id, payment_terms, tax_exempt,
                   custom_fields, tags, notes, logo_url, portal_enabled,
                   created_at, updated_at
            FROM companies
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );

        let count_query = format!("SELECT COUNT(*) FROM companies WHERE {count_where}");

        // Execute queries
        let mut query_builder = sqlx::query_as::<_, CompanyRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);

        let mut count_builder = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(ref q) = filter.q {
            let search = format!("%{}%", q);
            query_builder = query_builder.bind(search.clone());
            count_builder = count_builder.bind(search);
        }
        if let Some(ref ct) = filter.company_type {
            query_builder = query_builder.bind(ct.as_str());
            count_builder = count_builder.bind(ct.as_str());
        }
        if let Some(ref status) = filter.status {
            query_builder = query_builder.bind(status.as_str());
            count_builder = count_builder.bind(status.as_str());
        }
        if let Some(ref am_id) = filter.account_manager_id {
            query_builder = query_builder.bind(am_id);
            count_builder = count_builder.bind(am_id);
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = query_builder.fetch_all(&mut *tx).await?;
        let total = count_builder.fetch_one(&mut *tx).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Update company
    // The dynamic-update pattern increments `param_idx` after each
    // conditional bind so additional fields can be appended without
    // reflowing the chain. The final `+= 1` looks dead today but keeps
    // the next added field one diff away.
    #[allow(unused_assignments)]
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_company(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        request: &UpdateCompanyRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Company> {
        // Verify company exists
        self.get_company(tenant_id, company_id).await?;

        // PSA audit: validate any foreign id being set so an update cannot
        // re-link this company to another tenant's rows.
        self.validate_fk_opt(tenant_id, "companies", request.parent_company_id)
            .await?;
        self.validate_fk_opt(tenant_id, "users", request.account_manager_id)
            .await?;
        self.validate_fk_opt(tenant_id, "sla_policies", request.sla_id)
            .await?;

        // Build the dynamic UPDATE the same way update_site does. The
        // previous implementation only handled name / company_type /
        // status; everything else on UpdateCompanyRequest (industry,
        // website, phone, address, billing_address, payment_terms,
        // tax_exempt, custom_fields, tags, notes, portal_enabled) was
        // silently dropped on a 200 OK. Same family of bug as F4 was
        // for sites.
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if request.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if request.parent_company_id.is_some() {
            updates.push(format!("parent_company_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.company_type.is_some() {
            updates.push(format!("company_type = ${param_idx}"));
            param_idx += 1;
        }
        if request.status.is_some() {
            updates.push(format!("status = ${param_idx}"));
            param_idx += 1;
        }
        if request.industry.is_some() {
            updates.push(format!("industry = ${param_idx}"));
            param_idx += 1;
        }
        if request.website.is_some() {
            updates.push(format!("website = ${param_idx}"));
            param_idx += 1;
        }
        if request.phone.is_some() {
            updates.push(format!("phone = ${param_idx}"));
            param_idx += 1;
        }
        if request.fax.is_some() {
            updates.push(format!("fax = ${param_idx}"));
            param_idx += 1;
        }
        if request.address.is_some() {
            updates.push(format!("address_line1 = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("address_line2 = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("city = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("state = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("postal_code = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("country = ${param_idx}"));
            param_idx += 1;
        }
        if request.billing_address.is_some() {
            updates.push(format!("billing_address_line1 = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("billing_address_line2 = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("billing_city = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("billing_state = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("billing_postal_code = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("billing_country = ${param_idx}"));
            param_idx += 1;
        }
        if request.tax_id.is_some() {
            updates.push(format!("tax_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.account_number.is_some() {
            updates.push(format!("account_number = ${param_idx}"));
            param_idx += 1;
        }
        if request.default_billing_contact_id.is_some() {
            updates.push(format!("default_billing_contact_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.default_technical_contact_id.is_some() {
            updates.push(format!("default_technical_contact_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.account_manager_id.is_some() {
            updates.push(format!("account_manager_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.sla_id.is_some() {
            updates.push(format!("sla_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.default_contract_id.is_some() {
            updates.push(format!("default_contract_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.payment_terms.is_some() {
            updates.push(format!("payment_terms = ${param_idx}"));
            param_idx += 1;
        }
        if request.tax_exempt.is_some() {
            updates.push(format!("tax_exempt = ${param_idx}"));
            param_idx += 1;
        }
        if request.custom_fields.is_some() {
            updates.push(format!("custom_fields = ${param_idx}"));
            param_idx += 1;
        }
        if request.tags.is_some() {
            updates.push(format!("tags = ${param_idx}"));
            param_idx += 1;
        }
        if request.notes.is_some() {
            updates.push(format!("notes = ${param_idx}"));
            param_idx += 1;
        }
        if request.portal_enabled.is_some() {
            updates.push(format!("portal_enabled = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE companies SET {} WHERE tenant_id = $1 AND id = $2",
            updates.join(", ")
        );

        let mut q = sqlx::query(&query).bind(tenant_id).bind(company_id);

        if let Some(ref name) = request.name {
            q = q.bind(name);
        }
        if let Some(pcid) = request.parent_company_id {
            q = q.bind(pcid);
        }
        if let Some(ct) = request.company_type {
            q = q.bind(ct.as_str());
        }
        if let Some(status) = request.status {
            q = q.bind(status.as_str());
        }
        if let Some(ref industry) = request.industry {
            q = q.bind(industry);
        }
        if let Some(ref website) = request.website {
            q = q.bind(website);
        }
        if let Some(ref phone) = request.phone {
            q = q.bind(phone);
        }
        if let Some(ref fax) = request.fax {
            q = q.bind(fax);
        }
        if let Some(ref addr) = request.address {
            q = q
                .bind(&addr.line1)
                .bind(&addr.line2)
                .bind(&addr.city)
                .bind(&addr.state)
                .bind(&addr.postal_code)
                .bind(&addr.country);
        }
        if let Some(ref billing) = request.billing_address {
            q = q
                .bind(&billing.line1)
                .bind(&billing.line2)
                .bind(&billing.city)
                .bind(&billing.state)
                .bind(&billing.postal_code)
                .bind(&billing.country);
        }
        if let Some(ref tax_id) = request.tax_id {
            q = q.bind(tax_id);
        }
        if let Some(ref account_number) = request.account_number {
            q = q.bind(account_number);
        }
        if let Some(billing_id) = request.default_billing_contact_id {
            q = q.bind(billing_id);
        }
        if let Some(technical_id) = request.default_technical_contact_id {
            q = q.bind(technical_id);
        }
        if let Some(am_id) = request.account_manager_id {
            q = q.bind(am_id);
        }
        if let Some(sla_id) = request.sla_id {
            q = q.bind(sla_id);
        }
        if let Some(contract_id) = request.default_contract_id {
            q = q.bind(contract_id);
        }
        if let Some(ref payment_terms) = request.payment_terms {
            q = q.bind(payment_terms);
        }
        if let Some(tax_exempt) = request.tax_exempt {
            q = q.bind(tax_exempt);
        }
        if let Some(ref custom_fields) = request.custom_fields {
            q = q.bind(custom_fields);
        }
        if let Some(ref tags) = request.tags {
            q = q.bind(tags);
        }
        if let Some(ref notes) = request.notes {
            q = q.bind(notes);
        }
        if let Some(portal_enabled) = request.portal_enabled {
            q = q.bind(portal_enabled);
        }

        // Mutation + audit row in one transaction: snapshot the row
        // before and after (Postgres to_jsonb captures exact stored
        // state) and write the audit entry on the same tx so a rollback
        // drops both. PMS-117 AC1.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM companies c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;

        q.execute(&mut *tx).await?;

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM companies c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "companies",
            Some(company_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_company(tenant_id, company_id).await
    }

    /// Delete company
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_company(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117. The pre-flight
        // ticket guard runs inside the same tenant-scoped tx so the RLS
        // GUC is set for it too.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Check for related records
        let ticket_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND company_id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(&mut *tx)
        .await?;

        if ticket_count > 0 {
            return Err(AppError::BadRequest(
                "Cannot delete company with existing tickets".to_string(),
            ));
        }

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM companies c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;

        // The explicit ticket guard above only covers one of the many tables
        // that foreign-key `companies` (contracts, invoices, payments,
        // projects, assets, time entries, appointments, sub-companies, ...).
        // Those references are `ON DELETE RESTRICT`, so the DELETE raises
        // Postgres `23503`; map it to a 400 instead of letting the generic
        // `From<sqlx::Error>` turn it into a 500 (PMS-170, same shape as the
        // PMS-149 ticket-delete fix).
        if let Err(e) = sqlx::query("DELETE FROM companies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(company_id)
            .execute(&mut *tx)
            .await
        {
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23503") {
                return Err(AppError::BadRequest(
                    "Cannot delete company with related records (contracts, invoices, \
                     payments, projects, assets, time entries, appointments, or \
                     sub-companies); remove them first"
                        .to_string(),
                ));
            }
            return Err(e.into());
        }

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "companies",
            Some(company_id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;

        Ok(())
    }

    // ========================================================================
    // CONTACTS
    // ========================================================================

    /// Mint a single-use portal setup token bound to `contact_id` and
    /// insert it within the caller's transaction. The emailed token is
    /// `{contact_id}.{secret}`; only the Argon2 hash of the secret is
    /// stored (mirrors the password-reset token shape in
    /// `auth::service`). Returns the full token to email after the
    /// transaction commits. PMS-136.
    async fn insert_setup_token(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<String> {
        let secret = generate_token(64);
        let token_hash = hash_password(&secret)?;
        let token = format!("{contact_id}.{secret}");
        let expires_at = Utc::now() + Duration::hours(PORTAL_SETUP_TOKEN_TTL_HOURS);
        sqlx::query(
            r#"
            INSERT INTO portal_setup_tokens (tenant_id, contact_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(conn)
        .await?;
        Ok(token)
    }

    /// Best-effort delivery of the portal setup-link email. Called AFTER
    /// the grant transaction commits, so a failed send never rolls back
    /// the flag flip / token row; the token is persisted and the link can
    /// be resent later. A contact with no email address is skipped (the
    /// agent owns following up out of band). PMS-136.
    async fn send_setup_email(&self, contact: &Contact, token: &str) {
        let Some(ref email) = contact.email else {
            tracing::warn!(
                contact_id = %contact.id,
                "portal access granted but contact has no email; setup link not delivered",
            );
            return;
        };
        let setup_link = format!(
            "{}/portal/set-password?token={}",
            self.app_url.trim_end_matches('/'),
            token,
        );
        match self
            .mailer
            .send_welcome(email, &contact.first_name, &setup_link)
            .await
        {
            Ok(()) => tracing::info!(contact_id = %contact.id, "portal setup-link email sent"),
            Err(e) => tracing::warn!(
                contact_id = %contact.id,
                error = ?e,
                "portal setup email send failed; token persisted but link unreachable",
            ),
        }
    }

    /// Create a new contact
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_contact(
        &self,
        tenant_id: TenantId,
        request: &CreateContactRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Contact> {
        // Verify company exists
        self.get_company(tenant_id, request.company_id).await?;

        let contact_id = Uuid::new_v4();
        let timezone = request
            .timezone
            .clone()
            .unwrap_or_else(|| "UTC".to_string());

        // Mutation + audit row in one transaction so a rollback drops
        // both. CREATE: old = None, after captured by the new row id.
        // PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO contacts (
                id, tenant_id, company_id, first_name, last_name, email,
                phone, mobile, fax, title, department, contact_type,
                preferred_contact_method, timezone, custom_fields, tags, notes
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
            )
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .bind(request.company_id)
        .bind(&request.first_name)
        .bind(&request.last_name)
        .bind(&request.email)
        .bind(&request.phone)
        .bind(&request.mobile)
        .bind(&request.fax)
        .bind(&request.title)
        .bind(&request.department)
        .bind(request.contact_type.as_str())
        .bind("email") // preferred_contact_method
        .bind(&timezone)
        .bind(&request.custom_fields)
        .bind(&request.tags)
        .bind(&request.notes)
        .execute(&mut *tx)
        .await?;

        // PMS-19 / PMS-136: flip the contact's `is_portal_user` flag so the
        // portal-login flow (PMS-26) treats it as a valid identity, and mint
        // a single-use setup token. We deliberately do NOT mint a
        // `portal_password_hash` here: the password-set step belongs to the
        // customer, who redeems the emailed `/portal/set-password` link. The
        // token row is written inside this transaction so a rollback drops it
        // with the contact; the email is sent only after commit.
        let setup_token = if request.create_portal_access {
            sqlx::query(
                "UPDATE contacts SET is_portal_user = TRUE, updated_at = NOW() WHERE id = $1",
            )
            .bind(contact_id)
            .execute(&mut *tx)
            .await?;
            Some(
                self.insert_setup_token(&mut tx, tenant_id, contact_id)
                    .await?,
            )
        } else {
            None
        };

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM contacts c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "contacts",
            Some(contact_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        let contact = self.get_contact(tenant_id, contact_id).await?;
        // Email the setup link only after the grant transaction committed.
        if let Some(token) = setup_token {
            self.send_setup_email(&contact, &token).await;
        }
        Ok(contact)
    }

    /// Get contact by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_contact(&self, tenant_id: TenantId, contact_id: Uuid) -> AppResult<Contact> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, ContactRow>(
            r#"
            SELECT id, tenant_id, company_id, first_name, last_name, email,
                   phone, mobile, fax, title, department, contact_type,
                   is_portal_user, portal_user_id, preferred_contact_method,
                   timezone, locale, custom_fields, tags, notes, avatar_url,
                   status, created_at, updated_at
            FROM contacts
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Contact".to_string()))?;

        Ok(row.into())
    }

    /// List contacts with filters
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_contacts(
        &self,
        tenant_id: TenantId,
        filter: &ContactFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Contact>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        // Parallel WHERE clauses so the data and count queries each get
        // correctly numbered placeholders. data has $1 tenant + $2 limit
        // + $3 offset → filter binds at $4+; count has $1 tenant only →
        // filter binds at $2+.
        let mut data_conds = vec!["tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;

        if filter.q.is_some() {
            data_conds.push(format!(
                "(first_name ILIKE ${idx} OR last_name ILIKE ${idx} OR email ILIKE ${idx})",
                idx = data_idx
            ));
            count_conds.push(format!(
                "(first_name ILIKE ${idx} OR last_name ILIKE ${idx} OR email ILIKE ${idx})",
                idx = count_idx
            ));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.company_id.is_some() {
            data_conds.push(format!("company_id = ${data_idx}"));
            count_conds.push(format!("company_id = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.contact_type.is_some() {
            data_conds.push(format!("contact_type = ${data_idx}"));
            count_conds.push(format!("contact_type = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.status.is_some() {
            data_conds.push(format!("status = ${data_idx}"));
            count_conds.push(format!("status = ${count_idx}"));
        }

        let data_where = data_conds.join(" AND ");
        let count_where = count_conds.join(" AND ");
        let order_by = pagination.order_by(
            "last_name",
            &["first_name", "last_name", "email", "created_at"],
        );

        let query = format!(
            r#"
            SELECT id, tenant_id, company_id, first_name, last_name, email,
                   phone, mobile, fax, title, department, contact_type,
                   is_portal_user, portal_user_id, preferred_contact_method,
                   timezone, locale, custom_fields, tags, notes, avatar_url,
                   status, created_at, updated_at
            FROM contacts
            WHERE {data_where}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );

        let count_query = format!("SELECT COUNT(*) FROM contacts WHERE {count_where}");

        let mut query_builder = sqlx::query_as::<_, ContactRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);

        let mut count_builder = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);

        if let Some(ref q) = filter.q {
            let search = format!("%{}%", q);
            query_builder = query_builder.bind(search.clone());
            count_builder = count_builder.bind(search);
        }
        if let Some(ref company_id) = filter.company_id {
            query_builder = query_builder.bind(company_id);
            count_builder = count_builder.bind(company_id);
        }
        if let Some(ref ct) = filter.contact_type {
            query_builder = query_builder.bind(ct.as_str());
            count_builder = count_builder.bind(ct.as_str());
        }
        if let Some(ref status) = filter.status {
            query_builder = query_builder.bind(status.as_str());
            count_builder = count_builder.bind(status.as_str());
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = query_builder.fetch_all(&mut *tx).await?;
        let total = count_builder.fetch_one(&mut *tx).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Get contacts for a company
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_company_contacts(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Contact>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM contacts WHERE tenant_id = $1 AND company_id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, ContactRow>(
            r#"
            SELECT id, tenant_id, company_id, first_name, last_name, email,
                   phone, mobile, fax, title, department, contact_type,
                   is_portal_user, portal_user_id, preferred_contact_method,
                   timezone, locale, custom_fields, tags, notes, avatar_url,
                   status, created_at, updated_at
            FROM contacts
            WHERE tenant_id = $1 AND company_id = $2
            ORDER BY contact_type, last_name
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Update contact
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_contact(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        request: &UpdateContactRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Contact> {
        self.get_contact(tenant_id, contact_id).await?;

        // Mutation + audit row in one transaction: snapshot before and
        // after, write the audit entry on the same tx. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM contacts c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?;

        // Reject moving the contact to a foreign tenant's company. Same
        // shape as the create-time validate_fk path above.
        self.validate_fk_opt(tenant_id, "companies", request.company_id)
            .await?;

        // Build the dynamic UPDATE the same way update_site does, so
        // every field in UpdateContactRequest round-trips instead of
        // being silently dropped. The previous implementation only
        // handled first_name / last_name / email and 200-OK'd writes to
        // title, department, phone, mobile, etc.; same family of bug as
        // F4 was for sites.
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if request.company_id.is_some() {
            updates.push(format!("company_id = ${param_idx}"));
            param_idx += 1;
        }
        if request.first_name.is_some() {
            updates.push(format!("first_name = ${param_idx}"));
            param_idx += 1;
        }
        if request.last_name.is_some() {
            updates.push(format!("last_name = ${param_idx}"));
            param_idx += 1;
        }
        if request.email.is_some() {
            updates.push(format!("email = ${param_idx}"));
            param_idx += 1;
        }
        if request.phone.is_some() {
            updates.push(format!("phone = ${param_idx}"));
            param_idx += 1;
        }
        if request.mobile.is_some() {
            updates.push(format!("mobile = ${param_idx}"));
            param_idx += 1;
        }
        if request.fax.is_some() {
            updates.push(format!("fax = ${param_idx}"));
            param_idx += 1;
        }
        if request.title.is_some() {
            updates.push(format!("title = ${param_idx}"));
            param_idx += 1;
        }
        if request.department.is_some() {
            updates.push(format!("department = ${param_idx}"));
            param_idx += 1;
        }
        if request.contact_type.is_some() {
            updates.push(format!("contact_type = ${param_idx}"));
            param_idx += 1;
        }
        if request.preferred_contact_method.is_some() {
            updates.push(format!("preferred_contact_method = ${param_idx}"));
            param_idx += 1;
        }
        if request.timezone.is_some() {
            updates.push(format!("timezone = ${param_idx}"));
            param_idx += 1;
        }
        if request.custom_fields.is_some() {
            updates.push(format!("custom_fields = ${param_idx}"));
            param_idx += 1;
        }
        if request.tags.is_some() {
            updates.push(format!("tags = ${param_idx}"));
            param_idx += 1;
        }
        if request.notes.is_some() {
            updates.push(format!("notes = ${param_idx}"));
            param_idx += 1;
        }
        if request.status.is_some() {
            updates.push(format!("status = ${param_idx}"));
            param_idx += 1;
        }
        // PMS-136: persist the portal-access flag for any explicit value so a
        // grant (`true`) or revoke (`false`) round-trips. The setup-token mint
        // + email is gated on the false -> true transition below; flipping the
        // column here keeps a re-grant idempotent and a revoke effective.
        if request.is_portal_user.is_some() {
            updates.push(format!("is_portal_user = ${param_idx}"));
            // param_idx += 1; // last bound field
        }

        let query = format!(
            "UPDATE contacts SET {} WHERE tenant_id = $1 AND id = $2",
            updates.join(", ")
        );
        let mut q = sqlx::query(&query).bind(tenant_id).bind(contact_id);

        if let Some(cid) = request.company_id {
            q = q.bind(cid);
        }
        if let Some(ref first_name) = request.first_name {
            q = q.bind(first_name);
        }
        if let Some(ref last_name) = request.last_name {
            q = q.bind(last_name);
        }
        if let Some(ref email) = request.email {
            q = q.bind(email);
        }
        if let Some(ref phone) = request.phone {
            q = q.bind(phone);
        }
        if let Some(ref mobile) = request.mobile {
            q = q.bind(mobile);
        }
        if let Some(ref fax) = request.fax {
            q = q.bind(fax);
        }
        if let Some(ref title) = request.title {
            q = q.bind(title);
        }
        if let Some(ref department) = request.department {
            q = q.bind(department);
        }
        if let Some(ct) = request.contact_type {
            q = q.bind(ct.as_str());
        }
        if let Some(method) = request.preferred_contact_method {
            // PreferredContactMethod has no as_str(); spell the mapping
            // here to match the table's CHECK constraint ('email',
            // 'phone', 'mobile').
            let s = match method {
                crate::modules::contacts::PreferredContactMethod::Email => "email",
                crate::modules::contacts::PreferredContactMethod::Phone => "phone",
                crate::modules::contacts::PreferredContactMethod::Mobile => "mobile",
            };
            q = q.bind(s);
        }
        if let Some(ref timezone) = request.timezone {
            q = q.bind(timezone);
        }
        if let Some(ref custom_fields) = request.custom_fields {
            q = q.bind(custom_fields);
        }
        if let Some(ref tags) = request.tags {
            q = q.bind(tags);
        }
        if let Some(ref notes) = request.notes {
            q = q.bind(notes);
        }
        if let Some(status) = request.status {
            q = q.bind(status.as_str());
        }
        if let Some(is_portal_user) = request.is_portal_user {
            q = q.bind(is_portal_user);
        }

        q.execute(&mut *tx).await?;

        // PMS-136: a false -> true transition mints a single-use setup token
        // and (after commit) emails the contact a `/portal/set-password` link.
        // The prior `is_portal_user` is read off the `before` snapshot taken at
        // the top of this tx, so re-saving an already-portal contact does not
        // mint a second token or resend the email.
        let was_portal_user = before
            .as_ref()
            .and_then(|v| v.get("is_portal_user"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let setup_token = if request.is_portal_user == Some(true) && !was_portal_user {
            Some(
                self.insert_setup_token(&mut tx, tenant_id, contact_id)
                    .await?,
            )
        } else {
            None
        };

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM contacts c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(contact_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        let contact = self.get_contact(tenant_id, contact_id).await?;
        // Email the setup link only after the grant transaction committed.
        if let Some(token) = setup_token {
            self.send_setup_email(&contact, &token).await;
        }
        Ok(contact)
    }

    /// Delete contact
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_contact(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM contacts c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM contacts WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(contact_id)
            .execute(&mut *tx)
            .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "contacts",
            Some(contact_id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;

        Ok(())
    }

    // ========================================================================
    // SITES
    // ========================================================================

    /// Create a new site
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_site(
        &self,
        tenant_id: TenantId,
        request: &CreateSiteRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Site> {
        self.get_company(tenant_id, request.company_id).await?;

        let site_id = Uuid::new_v4();
        let address = request.address.clone().unwrap_or_default();
        let timezone = request
            .timezone
            .clone()
            .unwrap_or_else(|| "UTC".to_string());

        // Mutation + audit row in one transaction so a rollback drops
        // both. CREATE: old = None, after captured by the new row id.
        // PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // If this is marked as primary, unmark other sites
        if request.is_primary {
            sqlx::query(
                "UPDATE sites SET is_primary = FALSE WHERE tenant_id = $1 AND company_id = $2",
            )
            .bind(tenant_id)
            .bind(request.company_id)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            r#"
            INSERT INTO sites (
                id, tenant_id, company_id, name,
                address_line1, address_line2, city, state, postal_code, country,
                phone, is_primary, timezone, notes, latitude, longitude
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
            )
            "#,
        )
        .bind(site_id)
        .bind(tenant_id)
        .bind(request.company_id)
        .bind(&request.name)
        .bind(&address.line1)
        .bind(&address.line2)
        .bind(&address.city)
        .bind(&address.state)
        .bind(&address.postal_code)
        .bind(&address.country)
        .bind(&request.phone)
        .bind(request.is_primary)
        .bind(&timezone)
        .bind(&request.notes)
        .bind(request.latitude)
        .bind(request.longitude)
        .execute(&mut *tx)
        .await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(s) FROM sites s WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(site_id)
                .fetch_optional(&mut *tx)
                .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "sites",
            Some(site_id),
            None,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_site(tenant_id, site_id).await
    }

    /// Update a site. Audit F4: previously the route handler called
    /// `get_site` and silently returned the unchanged record.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_site(
        &self,
        tenant_id: TenantId,
        site_id: Uuid,
        request: &UpdateSiteRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Site> {
        // Verify site exists; also gives us the current company_id for
        // the is_primary unmark below.
        let current = self.get_site(tenant_id, site_id).await?;

        // Mutation + audit row in one transaction: snapshot before and
        // after, write the audit entry on the same tx. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(s) FROM sites s WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(site_id)
                .fetch_optional(&mut *tx)
                .await?;

        // If this is being marked primary, demote the other sites under
        // the same company first (mirrors create_site).
        if matches!(request.is_primary, Some(true)) {
            sqlx::query(
                "UPDATE sites SET is_primary = FALSE \
                 WHERE tenant_id = $1 AND company_id = $2 AND id <> $3",
            )
            .bind(tenant_id)
            .bind(current.company_id)
            .bind(site_id)
            .execute(&mut *tx)
            .await?;
        }

        // Build the dynamic UPDATE.
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if request.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if request.address.is_some() {
            updates.push(format!("address_line1 = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("address_line2 = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("city = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("state = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("postal_code = ${param_idx}"));
            param_idx += 1;
            updates.push(format!("country = ${param_idx}"));
            param_idx += 1;
        }
        if request.phone.is_some() {
            updates.push(format!("phone = ${param_idx}"));
            param_idx += 1;
        }
        if request.is_primary.is_some() {
            updates.push(format!("is_primary = ${param_idx}"));
            param_idx += 1;
        }
        if request.timezone.is_some() {
            updates.push(format!("timezone = ${param_idx}"));
            param_idx += 1;
        }
        if request.notes.is_some() {
            updates.push(format!("notes = ${param_idx}"));
            param_idx += 1;
        }
        if request.latitude.is_some() {
            updates.push(format!("latitude = ${param_idx}"));
            param_idx += 1;
        }
        if request.longitude.is_some() {
            updates.push(format!("longitude = ${param_idx}"));
            // param_idx += 1;
        }

        // No-op update (only `updated_at = NOW()`); just bump the row's
        // updated_at without rewriting columns.
        let query = format!(
            "UPDATE sites SET {} WHERE tenant_id = $1 AND id = $2",
            updates.join(", ")
        );

        let mut q = sqlx::query(&query).bind(tenant_id).bind(site_id);

        if let Some(ref name) = request.name {
            q = q.bind(name);
        }
        if let Some(ref addr) = request.address {
            q = q
                .bind(&addr.line1)
                .bind(&addr.line2)
                .bind(&addr.city)
                .bind(&addr.state)
                .bind(&addr.postal_code)
                .bind(&addr.country);
        }
        if let Some(ref phone) = request.phone {
            q = q.bind(phone);
        }
        if let Some(is_primary) = request.is_primary {
            q = q.bind(is_primary);
        }
        if let Some(ref timezone) = request.timezone {
            q = q.bind(timezone);
        }
        if let Some(ref notes) = request.notes {
            q = q.bind(notes);
        }
        if let Some(latitude) = request.latitude {
            q = q.bind(latitude);
        }
        if let Some(longitude) = request.longitude {
            q = q.bind(longitude);
        }

        q.execute(&mut *tx).await?;

        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(s) FROM sites s WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(site_id)
                .fetch_optional(&mut *tx)
                .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "sites",
            Some(site_id),
            before,
            after,
        )
        .await?;
        tx.commit().await?;

        self.get_site(tenant_id, site_id).await
    }

    /// Get site by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_site(&self, tenant_id: TenantId, site_id: Uuid) -> AppResult<Site> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row = sqlx::query_as::<_, SiteRow>(
            r#"
            SELECT id, tenant_id, company_id, name,
                   address_line1, address_line2, city, state, postal_code, country,
                   phone, is_primary, timezone, notes, latitude, longitude,
                   created_at, updated_at
            FROM sites
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(site_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Site".to_string()))?;

        Ok(row.into())
    }

    /// Get sites for a company
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_company_sites(
        &self,
        tenant_id: TenantId,
        company_id: Uuid,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Site>, u64)> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sites WHERE tenant_id = $1 AND company_id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(&mut *tx)
        .await?;

        let rows = sqlx::query_as::<_, SiteRow>(
            r#"
            SELECT id, tenant_id, company_id, name,
                   address_line1, address_line2, city, state, postal_code, country,
                   phone, is_primary, timezone, notes, latitude, longitude,
                   created_at, updated_at
            FROM sites
            WHERE tenant_id = $1 AND company_id = $2
            ORDER BY is_primary DESC, name
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&mut *tx)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Delete site
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_site(
        &self,
        tenant_id: TenantId,
        site_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Mutation + audit row in one transaction. DELETE: snapshot
        // before, old = before, after = None. PMS-117.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let before: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(s) FROM sites s WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(site_id)
                .fetch_optional(&mut *tx)
                .await?;

        sqlx::query("DELETE FROM sites WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(site_id)
            .execute(&mut *tx)
            .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "sites",
            Some(site_id),
            before,
            None,
        )
        .await?;
        tx.commit().await?;

        Ok(())
    }
}

// ============================================================================
// DATABASE ROW TYPES
// ============================================================================

#[derive(sqlx::FromRow)]
struct CompanyRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    parent_company_id: Option<Uuid>,
    company_type: String,
    status: String,
    industry: Option<String>,
    website: Option<String>,
    phone: Option<String>,
    fax: Option<String>,
    address_line1: Option<String>,
    address_line2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    billing_address_line1: Option<String>,
    billing_address_line2: Option<String>,
    billing_city: Option<String>,
    billing_state: Option<String>,
    billing_postal_code: Option<String>,
    billing_country: Option<String>,
    tax_id: Option<String>,
    account_number: Option<String>,
    default_billing_contact_id: Option<Uuid>,
    default_technical_contact_id: Option<Uuid>,
    account_manager_id: Option<Uuid>,
    sla_id: Option<Uuid>,
    default_contract_id: Option<Uuid>,
    payment_terms: Option<String>,
    tax_exempt: bool,
    custom_fields: serde_json::Value,
    tags: Vec<String>,
    notes: Option<String>,
    logo_url: Option<String>,
    portal_enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<CompanyRow> for Company {
    fn from(row: CompanyRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            parent_company_id: row.parent_company_id,
            company_type: CompanyType::from_str(&row.company_type).unwrap_or_default(),
            status: CompanyStatus::from_str(&row.status).unwrap_or_default(),
            industry: row.industry,
            website: row.website,
            phone: row.phone,
            fax: row.fax,
            address: Address {
                line1: row.address_line1,
                line2: row.address_line2,
                city: row.city,
                state: row.state,
                postal_code: row.postal_code,
                country: row.country,
            },
            billing_address: Address {
                line1: row.billing_address_line1,
                line2: row.billing_address_line2,
                city: row.billing_city,
                state: row.billing_state,
                postal_code: row.billing_postal_code,
                country: row.billing_country,
            },
            tax_id: row.tax_id,
            account_number: row.account_number,
            default_billing_contact_id: row.default_billing_contact_id,
            default_technical_contact_id: row.default_technical_contact_id,
            account_manager_id: row.account_manager_id,
            sla_id: row.sla_id,
            default_contract_id: row.default_contract_id,
            payment_terms: row.payment_terms,
            tax_exempt: row.tax_exempt,
            custom_fields: row.custom_fields,
            tags: row.tags,
            notes: row.notes,
            logo_url: row.logo_url,
            portal_enabled: row.portal_enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Rollup row returned by `enrich_companies`. The four count columns
/// are non-null because the subqueries always return a number (COUNT
/// over an empty set is 0).
#[derive(sqlx::FromRow)]
struct CompanyRollupRow {
    company_id: Uuid,
    account_manager_name: Option<String>,
    contact_count: i64,
    site_count: i64,
    open_ticket_count: i64,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)] // FromRow mirrors the contacts column set; not every column is exposed on Contact yet.
struct ContactRow {
    id: Uuid,
    tenant_id: Uuid,
    company_id: Uuid,
    first_name: String,
    last_name: String,
    email: Option<String>,
    phone: Option<String>,
    mobile: Option<String>,
    fax: Option<String>,
    title: Option<String>,
    department: Option<String>,
    contact_type: String,
    is_portal_user: bool,
    portal_user_id: Option<Uuid>,
    preferred_contact_method: String,
    timezone: String,
    locale: String,
    custom_fields: serde_json::Value,
    tags: Vec<String>,
    notes: Option<String>,
    avatar_url: Option<String>,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ContactRow> for Contact {
    fn from(row: ContactRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            company_id: row.company_id,
            first_name: row.first_name,
            last_name: row.last_name,
            email: row.email,
            phone: row.phone,
            mobile: row.mobile,
            fax: row.fax,
            title: row.title,
            department: row.department,
            contact_type: ContactType::from_str(&row.contact_type).unwrap_or_default(),
            is_portal_user: row.is_portal_user,
            portal_user_id: row.portal_user_id,
            // PMS-195: honor the stored value instead of hardcoding Email.
            // Unknown values fall back to the enum default (Email), matching
            // the `contact_type` / `status` `unwrap_or_default()` pattern.
            preferred_contact_method: match row.preferred_contact_method.as_str() {
                "phone" => PreferredContactMethod::Phone,
                "mobile" => PreferredContactMethod::Mobile,
                _ => PreferredContactMethod::Email,
            },
            timezone: row.timezone,
            locale: row.locale,
            custom_fields: row.custom_fields,
            tags: row.tags,
            notes: row.notes,
            avatar_url: row.avatar_url,
            status: ContactStatus::from_str(&row.status).unwrap_or_default(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SiteRow {
    id: Uuid,
    tenant_id: Uuid,
    company_id: Uuid,
    name: String,
    address_line1: Option<String>,
    address_line2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    phone: Option<String>,
    is_primary: bool,
    timezone: String,
    notes: Option<String>,
    latitude: Option<rust_decimal::Decimal>,
    longitude: Option<rust_decimal::Decimal>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<SiteRow> for Site {
    fn from(row: SiteRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            company_id: row.company_id,
            name: row.name,
            address: Address {
                line1: row.address_line1,
                line2: row.address_line2,
                city: row.city,
                state: row.state,
                postal_code: row.postal_code,
                country: row.country,
            },
            phone: row.phone,
            is_primary: row.is_primary,
            timezone: row.timezone,
            notes: row.notes,
            latitude: row.latitude.map(|d| d.to_string().parse().unwrap_or(0.0)),
            longitude: row.longitude.map(|d| d.to_string().parse().unwrap_or(0.0)),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
