//! Contact service implementation

use crate::modules::auth::TenantId;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::notifications::NotificationsService;
use crate::utils::crypto::{generate_token, hash_password};
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
    /// Base URL of the customer-facing SPA. The setup link is
    /// `{app_url}/portal/set-password?token=...`.
    app_url: String,
    /// PMS-700: the setup mail is queued through the same `auth.welcome`
    /// dispatch the staff welcome mail uses, so both render one template and
    /// both get the worker's retries. `None` in fixtures built without a
    /// dispatcher, which then queue nothing.
    notifications: Option<NotificationsService>,
}

impl ContactService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            app_url: String::new(),
            notifications: None,
        }
    }

    /// Construct with the SPA base URL (the setup-link prefix) and the
    /// notifications dispatcher, so granting portal access queues the
    /// contact a setup link through the `auth.welcome` template
    /// (PMS-136, PMS-700). The server uses this constructor in
    /// `create_api_router`.
    pub fn with_dispatcher(
        db: Database,
        app_url: String,
        notifications: NotificationsService,
    ) -> Self {
        Self {
            db,
            app_url,
            notifications: Some(notifications),
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

        // PMS-400: reject a duplicate name within the tenant
        // (case-insensitive, trimmed) before the INSERT so the common path
        // returns a friendly 409. The unique index added in migration 054
        // closes the TOCTOU race between two concurrent creates.
        let name_taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM companies \
             WHERE tenant_id = $1 AND company_type <> 'internal' \
             AND lower(btrim(name)) = lower(btrim($2)))",
        )
        .bind(tenant_id)
        .bind(&request.name)
        .fetch_one(&mut *tx)
        .await?;
        if name_taken {
            return Err(AppError::Conflict(
                "A company with this name already exists".to_string(),
            ));
        }

        if let Err(e) = sqlx::query(
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
        .await
        {
            // Race backstop: another concurrent create won the unique index
            // (migration 054). Map 23505 to the same friendly 409 the
            // pre-flight check returns instead of a 500.
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                return Err(AppError::Conflict(
                    "A company with this name already exists".to_string(),
                ));
            }
            return Err(e.into());
        }

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
        let offset = pagination.offset() as i64;
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
        } else {
            // PMS-413: the default customer list excludes the tenant's internal
            // own-company so it never appears as a fake client in pickers. An
            // explicit `company_type=internal` filter (above branch) still
            // surfaces it, and lookup-by-id (`get_company`) is unaffected.
            data_conds.push("company_type <> 'internal'".to_string());
            count_conds.push("company_type <> 'internal'".to_string());
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

        // PMS-400: when renaming, reject a name already held by ANOTHER
        // company in the tenant (case-insensitive, trimmed). Excluding this
        // company's own id lets a re-save with the name unchanged succeed.
        if let Some(ref name) = request.name {
            let name_taken: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM companies \
                 WHERE tenant_id = $1 AND id <> $2 AND company_type <> 'internal' \
                 AND lower(btrim(name)) = lower(btrim($3)))",
            )
            .bind(tenant_id)
            .bind(company_id)
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
            if name_taken {
                return Err(AppError::Conflict(
                    "A company with this name already exists".to_string(),
                ));
            }
        }

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM companies c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Err(e) = q.execute(&mut *tx).await {
            // Race backstop against the unique index (migration 054).
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                return Err(AppError::Conflict(
                    "A company with this name already exists".to_string(),
                ));
            }
            return Err(e.into());
        }

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
    ///
    /// Portal-setup email dispatched at contact create + update time when
    /// `is_portal_user` flips true. Delegates to `send_grant_email` (prompt
    /// 011) so the URL carries the Company's portal_slug segment
    /// (`/portal/{slug}/set-password?token=...`), the Portal ID is surfaced,
    /// and the correct `auth.portal_grant` template renders. The prior
    /// implementation dispatched `auth.welcome` with a slug-less
    /// `/portal/set-password?token=...` URL that the SPA router 404'd on,
    /// stranding every fresh contact.
    async fn send_setup_email(&self, contact: &Contact, token: &str) {
        if contact.email.is_none() {
            tracing::warn!(
                contact_id = %contact.id,
                "portal access granted but contact has no email; setup link not delivered",
            );
            return;
        }
        let Some(company_id) = contact.company_id else {
            tracing::warn!(
                contact_id = %contact.id,
                "portal setup token minted but contact has no company_id; no Company portal to sign into, setup email not delivered",
            );
            return;
        };
        let portal_id = match self.ensure_portal_id(company_id, contact.tenant_id).await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    contact_id = %contact.id,
                    company_id = %company_id,
                    error = ?e,
                    "failed to ensure portal_id for grant email; setup email not delivered (token still redeemable via /portal/login finder)",
                );
                return;
            }
        };
        let portal_slug = match self.ensure_portal_slug(company_id, contact.tenant_id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    contact_id = %contact.id,
                    company_id = %company_id,
                    error = ?e,
                    "failed to ensure portal_slug for grant email; setup email not delivered (token still redeemable via /portal/login finder)",
                );
                return;
            }
        };
        self.send_grant_email(contact, &portal_slug, portal_id, token)
            .await;
    }

    /// Assign (or read) a Company's portal_slug. Mirrors `ensure_portal_id`'s
    /// shape: fast-path returns the existing value, retry-loop on UNIQUE
    /// collisions when minting a fresh candidate. `grant_portal_access` still
    /// runs its own inline slug-mint inside the grant tx so the assignment is
    /// atomic with the role writes; this helper covers the create + update
    /// paths where the enclosing tx is not the grant tx.
    async fn ensure_portal_slug(&self, company_id: Uuid, tenant_id: Uuid) -> AppResult<String> {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT portal_slug FROM companies WHERE id = $1 AND tenant_id = $2",
        )
        .bind(company_id)
        .bind(tenant_id)
        .fetch_optional(self.db.migrator_pool())
        .await?
        .flatten();
        if let Some(s) = existing {
            return Ok(s);
        }

        for _ in 0..5 {
            let candidate = crate::utils::crypto::generate_portal_slug();
            let update_result = sqlx::query(
                "UPDATE companies SET portal_slug = $1, updated_at = NOW() \
                 WHERE id = $2 AND tenant_id = $3 AND portal_slug IS NULL",
            )
            .bind(&candidate)
            .bind(company_id)
            .bind(tenant_id)
            .execute(self.db.migrator_pool())
            .await;

            match update_result {
                Ok(res) if res.rows_affected() == 1 => return Ok(candidate),
                Ok(_) => {
                    let now: Option<String> = sqlx::query_scalar(
                        "SELECT portal_slug FROM companies \
                         WHERE id = $1 AND tenant_id = $2",
                    )
                    .bind(company_id)
                    .bind(tenant_id)
                    .fetch_optional(self.db.migrator_pool())
                    .await?
                    .flatten();
                    if let Some(s) = now {
                        return Ok(s);
                    }
                    continue;
                }
                Err(sqlx::Error::Database(dbe)) if dbe.code().as_deref() == Some("23505") => {
                    continue;
                }
                Err(other) => return Err(other.into()),
            }
        }
        Err(AppError::Internal(
            "could not assign a unique portal_slug after 5 attempts".to_string(),
        ))
    }

    /// mokosh-contact-login prompt 003: list the portal roles the MSP
    /// admin can pick from when granting a contact portal access.
    /// Returns every row in `portal_roles` for the caller's tenant
    /// (including the three built-ins seeded by migration 142 +
    /// `TenantService::seed_builtin_portal_roles`).
    ///
    /// PMS-929 (prompt 012): `company_id = None` returns tenant-wide
    /// roles only (the historical shape; every existing caller still
    /// passes `None`). `company_id = Some(cid)` returns the union of
    /// tenant-wide roles plus that Company's own scoped roles, ordered
    /// built-in first, then tenant-wide customs, then Company-scoped,
    /// name-alphabetical inside each band. Same-name across scopes is
    /// intentionally allowed so both rows appear in the list.
    pub async fn list_portal_roles(
        &self,
        tenant_id: TenantId,
        company_id: Option<Uuid>,
    ) -> AppResult<Vec<PortalRoleSummary>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String, Vec<String>, bool, Option<Uuid>)> = match company_id {
            None => {
                sqlx::query_as(
                    "SELECT id, name, capabilities, is_builtin, company_id FROM portal_roles \
                 WHERE tenant_id = $1 AND company_id IS NULL \
                 ORDER BY is_builtin DESC, name",
                )
                .bind(*tenant_id)
                .fetch_all(&mut *tx)
                .await?
            }
            Some(cid) => {
                sqlx::query_as(
                    "SELECT id, name, capabilities, is_builtin, company_id FROM portal_roles \
                 WHERE tenant_id = $1 AND (company_id IS NULL OR company_id = $2) \
                 ORDER BY is_builtin DESC, company_id NULLS FIRST, name",
                )
                .bind(*tenant_id)
                .bind(cid)
                .fetch_all(&mut *tx)
                .await?
            }
        };
        Ok(rows
            .into_iter()
            .map(
                |(id, name, capabilities, is_builtin, company_id)| PortalRoleSummary {
                    id,
                    name,
                    capabilities,
                    is_builtin,
                    company_id,
                },
            )
            .collect())
    }

    /// mokosh-contact-login prompt 003: return the role ids currently
    /// assigned to a contact. Used by the SPA to pre-check boxes in the
    /// grant modal when opened on an already-portal-user contact.
    pub async fn list_contact_portal_role_ids(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<Vec<Uuid>> {
        // Verify the contact belongs to this tenant before returning
        // any row so a foreign contact_id fails closed with 404.
        let _contact = self.get_contact(tenant_id, contact_id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT role_id FROM contact_role_assignments \
             WHERE contact_id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(*tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(ids)
    }

    /// mokosh-contact-login prompt 003: grant portal access to a
    /// contact + assign one or more portal roles atomically.
    ///
    /// Mints (or reuses) the Company's `portal_slug`, rewrites the
    /// contact's `contact_role_assignments` to exactly `role_ids`,
    /// flips `contacts.is_portal_user = TRUE`, invalidates any prior
    /// unredeemed setup token, mints a fresh one, and dispatches the
    /// `auth.welcome` email carrying
    /// `{app_url}/portal/{slug}/set-password?token={contact_id}.{secret}`.
    ///
    /// Steps in one transaction (so a rollback wipes both the role
    /// assignments and the token row); the email dispatch is
    /// best-effort AFTER the tx commits so a mailer outage does not
    /// undo the grant. Returns `PortalGrantOutcome { portal_slug,
    /// setup_link }` so the SPA can display + copy the URL to the
    /// operator (useful when email delivery is delayed or the
    /// operator wants to relay it via chat).
    ///
    /// Guards:
    /// - Contact must exist under `tenant_id`.
    /// - Contact's `company_id` must NOT be the tenant's own_company
    ///   (own_company contacts are bookkeeping placeholders).
    /// - Every `role_ids[i]` must belong to the same tenant.
    /// - `role_ids` must be non-empty (a contact needs at least one
    ///   role to hold any capability).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id))]
    pub async fn grant_portal_access(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        role_ids: &[Uuid],
        ctx: &AuditCtx,
    ) -> AppResult<PortalGrantOutcome> {
        if role_ids.is_empty() {
            return Err(AppError::validation_field(
                "role_ids",
                "at least one portal role is required",
            ));
        }

        let contact = self.get_contact(tenant_id, contact_id).await?;

        // Portal access needs a company - the slug lives on the
        // companies row and every scoped query filters on
        // company_id. Freeform-company contacts (PMS-402) do not
        // have a company_id and cannot get portal access without
        // being linked to a real Company first.
        let Some(company_id) = contact.company_id else {
            return Err(AppError::BadRequest(
                "contact has no company_id; link the contact to a Company before granting portal access"
                    .to_string(),
            ));
        };

        // Refuse to grant on an own_company contact. Those rows are
        // internal bookkeeping (see `TenantService::ensure_own_company`)
        // and are never a real customer.
        let own_company_id: Option<Uuid> =
            sqlx::query_scalar("SELECT own_company_id FROM tenants WHERE id = $1")
                .bind(*tenant_id)
                .fetch_optional(self.db.pool())
                .await?
                .flatten();
        if own_company_id == Some(company_id) {
            return Err(AppError::BadRequest(
                "cannot grant portal access to a contact on the tenant's own_company".to_string(),
            ));
        }

        // Every submitted role must belong to this tenant AND be
        // scope-compatible with the target contact (tenant-wide, or
        // scoped to the SAME Company as the contact).
        //
        // PMS-929 (prompt 012): parallel to the scope check in
        // `replace_portal_role_assignments`. A wrong-Company role
        // would let the contact hold a capability scoped to a Company
        // they don't belong to. Read the (id, company_id) pairs in
        // one shot; a role missing from the result is either a foreign
        // tenant id or a scoped-to-other-Company id (invisible under
        // this query), both mapped to the same 400 shape so the
        // response never leaks scope existence.
        // Uses migrator_pool() (RLS-bypass) with the explicit `WHERE
        // tenant_id = $1` filter. Reading through self.db.pool() without a
        // begin_with_tenant() to set app.current_tenant makes RLS fail-close
        // to zero rows, which turned every submitted role_id into "role
        // missing" and 400'd every grant with the scope-mismatch message.
        // The explicit tenant_id in the WHERE clause is the tenant guard.
        let role_rows: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, company_id FROM portal_roles WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(*tenant_id)
        .bind(role_ids)
        .fetch_all(self.db.migrator_pool())
        .await?;
        let role_map: std::collections::HashMap<Uuid, Option<Uuid>> =
            role_rows.into_iter().collect();
        for role_id in role_ids {
            match role_map.get(role_id) {
                Some(role_company) => {
                    if let Some(rcid) = role_company {
                        if *rcid != company_id {
                            return Err(AppError::BadRequest(format!(
                                "Role {role_id} is scoped to a different Company than the target contact"
                            )));
                        }
                    }
                }
                None => {
                    return Err(AppError::BadRequest(format!(
                        "Role {role_id} is scoped to a different Company than the target contact"
                    )));
                }
            }
        }

        // mokosh-contact-login prompt 011 (PMS-928): ensure the Company
        // has a numeric portal_id. Runs BEFORE the tenant-bound
        // transaction opens because it does its own UPDATE (with
        // UNIQUE-constraint retries) against `companies`; running it
        // inside the grant tx would race the slug-assignment UPDATE
        // that follows and deadlock on the same row. Idempotent + safe
        // to run first: on grant failure the assigned portal_id stays,
        // which is harmless (a follow-up grant reuses it).
        let portal_id = self.ensure_portal_id(company_id, *tenant_id).await?;

        // Mint or reuse the Company's slug. Uses a small retry loop
        // in case `generate_portal_slug` returns a value already taken
        // by another Company (astronomically unlikely at 80 bits of
        // entropy, but cheap to guard).
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing_slug: Option<String> = sqlx::query_scalar(
            "SELECT portal_slug FROM companies WHERE id = $1 AND tenant_id = $2",
        )
        .bind(company_id)
        .bind(*tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .flatten();
        let portal_slug: String = match existing_slug {
            Some(s) => s,
            None => {
                let mut candidate = crate::utils::crypto::generate_portal_slug();
                for _ in 0..3 {
                    let updated: Option<String> = sqlx::query_scalar(
                        "UPDATE companies SET portal_slug = $1, updated_at = NOW() \
                         WHERE id = $2 AND tenant_id = $3 AND portal_slug IS NULL \
                         RETURNING portal_slug",
                    )
                    .bind(&candidate)
                    .bind(company_id)
                    .bind(*tenant_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .ok()
                    .flatten();
                    if let Some(s) = updated {
                        break;
                    }
                    // Either the slug was taken elsewhere (unique
                    // violation - refresh from disk) or a concurrent
                    // grant on the same Company populated it first.
                    // Re-read the row to see which.
                    let now: Option<String> = sqlx::query_scalar(
                        "SELECT portal_slug FROM companies \
                         WHERE id = $1 AND tenant_id = $2",
                    )
                    .bind(company_id)
                    .bind(*tenant_id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .flatten();
                    if let Some(s) = now {
                        candidate = s;
                        break;
                    }
                    // Neither branch fired: the candidate collided with
                    // ANOTHER Company. Mint a fresh one and retry.
                    candidate = crate::utils::crypto::generate_portal_slug();
                }
                // At this point either the UPDATE landed our candidate
                // (companies.portal_slug now holds it) or we absorbed
                // an existing value. Re-read to confirm.
                sqlx::query_scalar::<_, Option<String>>(
                    "SELECT portal_slug FROM companies WHERE id = $1 AND tenant_id = $2",
                )
                .bind(company_id)
                .bind(*tenant_id)
                .fetch_one(&mut *tx)
                .await?
                .ok_or_else(|| {
                    AppError::Internal(
                        "portal slug still NULL after generate_portal_slug retries".to_string(),
                    )
                })?
            }
        };

        // Rewrite the role assignments: delete anything not in the new
        // set, upsert the new set. Atomic + idempotent so re-invoking
        // with the same set is a no-op and re-invoking with a smaller
        // set drops the removed rows.
        sqlx::query(
            "DELETE FROM contact_role_assignments \
             WHERE contact_id = $1 AND tenant_id = $2 AND NOT (role_id = ANY($3))",
        )
        .bind(contact_id)
        .bind(*tenant_id)
        .bind(role_ids)
        .execute(&mut *tx)
        .await?;
        for role_id in role_ids {
            sqlx::query(
                "INSERT INTO contact_role_assignments (contact_id, role_id, tenant_id) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (contact_id, role_id) DO NOTHING",
            )
            .bind(contact_id)
            .bind(role_id)
            .bind(*tenant_id)
            .execute(&mut *tx)
            .await?;
        }

        // Flip is_portal_user if it is not already TRUE. Bookkeeping,
        // and (post-pivot) belt-and-braces: the contact plane's login
        // handler will also gate on `is_portal_user = TRUE`.
        sqlx::query(
            "UPDATE contacts SET is_portal_user = TRUE, updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(*tenant_id)
        .execute(&mut *tx)
        .await?;

        // Invalidate every prior unredeemed setup token for this
        // contact so only the freshly minted link works.
        sqlx::query(
            "DELETE FROM portal_setup_tokens \
             WHERE tenant_id = $1 AND contact_id = $2 AND used_at IS NULL",
        )
        .bind(*tenant_id)
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        let token = self
            .insert_setup_token(&mut tx, tenant_id, contact_id)
            .await?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(contact_id),
            None,
            Some(serde_json::json!({
                "portal_access_granted": true,
                "role_ids": role_ids,
            })),
        )
        .await?;
        tx.commit().await?;

        let setup_link = format!(
            "{}/portal/{}/set-password?token={}",
            self.app_url.trim_end_matches('/'),
            portal_slug,
            token,
        );
        self.send_grant_email(&contact, &portal_slug, portal_id, &token)
            .await;

        Ok(PortalGrantOutcome {
            portal_slug,
            portal_id,
            setup_link,
        })
    }

    /// mokosh-contact-login prompt 011 (PMS-928): assign a 9-digit
    /// numeric Portal ID to the Company if one is not set. Fast-path
    /// returns the existing value; otherwise loops up to 5 attempts
    /// against `generate_portal_id`, UPDATE'ing only when
    /// `portal_id IS NULL` (so a concurrent grant that already won
    /// doesn't get overwritten). On a UNIQUE-constraint bounce (astro-
    /// nomically unlikely at 10M Companies over a 900M space, but
    /// cheap to guard) we retry with a fresh value; on 0 rows affected
    /// we re-read the row (someone else raced us and won), returning
    /// the value they installed. On 5 failed retries we surface an
    /// `Internal` so the grant fails loud rather than sitting on a
    /// slug-only Company.
    ///
    /// Not tenant-scoped inside the query (`WHERE id = $2 AND
    /// tenant_id = $3`) because the caller already validated the
    /// Company belongs to this tenant, but the `AND tenant_id = $3`
    /// keeps a stray cross-tenant call from silently touching another
    /// tenant's row.
    async fn ensure_portal_id(&self, company_id: Uuid, tenant_id: Uuid) -> AppResult<i64> {
        // Fast path: already assigned.
        let existing: Option<i64> =
            sqlx::query_scalar("SELECT portal_id FROM companies WHERE id = $1 AND tenant_id = $2")
                .bind(company_id)
                .bind(tenant_id)
                .fetch_optional(self.db.migrator_pool())
                .await?
                .flatten();
        if let Some(v) = existing {
            return Ok(v);
        }

        for _ in 0..5 {
            let candidate = crate::utils::crypto::generate_portal_id();
            let update_result = sqlx::query(
                "UPDATE companies SET portal_id = $1, updated_at = NOW() \
                 WHERE id = $2 AND tenant_id = $3 AND portal_id IS NULL",
            )
            .bind(candidate)
            .bind(company_id)
            .bind(tenant_id)
            .execute(self.db.migrator_pool())
            .await;

            match update_result {
                Ok(res) if res.rows_affected() == 1 => return Ok(candidate),
                Ok(_) => {
                    // 0 rows affected: another writer beat us and
                    // populated the row. Re-read and return their
                    // value. If somehow still NULL, fall through to
                    // the retry loop (the guard we just lost was
                    // rolled back by the same writer, which is
                    // impossible given `SET portal_id = ...` cannot
                    // set back to NULL, so a NULL here means the row
                    // was deleted mid-flight and the caller should
                    // fail).
                    let now: Option<i64> = sqlx::query_scalar(
                        "SELECT portal_id FROM companies \
                         WHERE id = $1 AND tenant_id = $2",
                    )
                    .bind(company_id)
                    .bind(tenant_id)
                    .fetch_optional(self.db.migrator_pool())
                    .await?
                    .flatten();
                    if let Some(v) = now {
                        return Ok(v);
                    }
                    // Row missing or still NULL: continue the retry
                    // loop; on the last iteration we surface Internal.
                    continue;
                }
                Err(sqlx::Error::Database(dbe)) if dbe.code().as_deref() == Some("23505") => {
                    // Value collided with another Company's portal_id.
                    // Retry with a fresh candidate.
                    continue;
                }
                Err(other) => return Err(other.into()),
            }
        }

        Err(AppError::Internal(
            "could not assign a unique Portal ID after 5 attempts".to_string(),
        ))
    }

    /// mokosh-contact-login prompt 003: resend the setup link to an
    /// existing portal contact. Invalidates any prior unredeemed
    /// token, mints a fresh one, dispatches the email. 400 when the
    /// contact is not `is_portal_user = TRUE` (grant first) or has no
    /// email on file.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id))]
    pub async fn resend_portal_invite(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let contact = self.get_contact(tenant_id, contact_id).await?;
        if !contact.is_portal_user {
            return Err(AppError::conflict(
                "contact does not have portal access; grant it first",
            ));
        }
        if contact.email.as_deref().unwrap_or("").trim().is_empty() {
            return Err(AppError::conflict(
                "contact has no email on file; add one before resending",
            ));
        }
        // mokosh-contact-login prompt 011 (PMS-928): a resend on an
        // older Company (granted before the portal_id migration
        // landed) may still hold a NULL portal_id. Ensure one is
        // present so the resent email carries the Portal ID header
        // and the new IAM-style login flow can use it.
        //
        // Self-heals a Company still missing portal_slug too - the
        // prior fail-hard branch left operators stuck ("portal access
        // is on but company has no portal_slug; re-grant") on any
        // Company granted before the ensure-slug landed in
        // create/update. Both ensure_ helpers are fast-path + retry
        // shaped so the happy path (slug already assigned) is a
        // single SELECT.
        let Some(company_id) = contact.company_id else {
            return Err(AppError::conflict(
                "contact has no company; attach one before resending the portal invite",
            ));
        };
        let portal_id = self.ensure_portal_id(company_id, *tenant_id).await?;
        let slug = self.ensure_portal_slug(company_id, *tenant_id).await?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "DELETE FROM portal_setup_tokens \
             WHERE tenant_id = $1 AND contact_id = $2 AND used_at IS NULL",
        )
        .bind(*tenant_id)
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        let token = self
            .insert_setup_token(&mut tx, tenant_id, contact_id)
            .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(contact_id),
            None,
            Some(serde_json::json!({ "portal_invite_resent": true })),
        )
        .await?;
        tx.commit().await?;

        self.send_grant_email(&contact, &slug, portal_id, &token)
            .await;
        Ok(())
    }

    /// mokosh-contact-login prompt 003: revoke portal access. Deletes
    /// the contact's role assignments, flips `is_portal_user = FALSE`,
    /// deletes any pending setup tokens, and marks every live
    /// `contact_sessions` row for this contact revoked so an in-flight
    /// access token dies on the next request-tick.
    ///
    /// Does NOT rotate the Company's slug; a later re-grant reuses it.
    /// Does NOT clear `portal_password_hash` so a re-grant preserves
    /// the customer's chosen password (they can log in again without
    /// re-setting).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id))]
    pub async fn revoke_portal_access(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        // Verify the contact exists under this tenant before mutating.
        let _contact = self.get_contact(tenant_id, contact_id).await?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "DELETE FROM contact_role_assignments WHERE contact_id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(*tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE contacts SET is_portal_user = FALSE, updated_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(*tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM portal_setup_tokens \
             WHERE tenant_id = $1 AND contact_id = $2 AND used_at IS NULL",
        )
        .bind(*tenant_id)
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        // Revoke live sessions so the pre-revoke access token dies on
        // the next request (mirrors MAPPS-557 on the retired portal
        // plane; prompt 004's contact-auth middleware re-checks this
        // on every hit).
        sqlx::query(
            "UPDATE contact_sessions SET revoked_at = NOW() \
             WHERE tenant_id = $1 AND contact_id = $2 AND revoked_at IS NULL",
        )
        .bind(*tenant_id)
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(contact_id),
            None,
            Some(serde_json::json!({ "portal_access_revoked": true })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// mokosh-contact-login prompt 007: replace the contact's portal
    /// role assignments with `role_ids`. Distinct from
    /// `grant_portal_access` (which mints/rotates the setup token,
    /// flips `is_portal_user`, and emails the invite): the role editor
    /// on the contact page just rewires the assignment set for an
    /// already-portal contact. No side effects on `is_portal_user`, no
    /// token churn, no email.
    ///
    /// Empty `role_ids` is allowed and clears the assignment set (a
    /// portal user with zero roles has no capabilities and can log in
    /// but see nothing gated; the operator either re-adds a role or
    /// revokes access outright).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id, contact_id = %contact_id))]
    pub async fn replace_portal_role_assignments(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        role_ids: &[Uuid],
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let contact = self.get_contact(tenant_id, contact_id).await?;

        // Dedup the caller's list so a repeated id doesn't fight the
        // (contact_id, role_id) primary key.
        let mut unique: Vec<Uuid> = role_ids.to_vec();
        unique.sort();
        unique.dedup();

        // PMS-929 (prompt 012): every role must both exist in this
        // tenant AND (be tenant-wide OR be scoped to the SAME Company
        // as the contact). Wrong-Company assignments would let a
        // contact hold a capability scoped to a Company they don't
        // belong to; the picker filters on read, this is the write-side
        // enforcement. Read the (tenant_id, company_id) pair of every
        // role in one shot; a role missing from the result means
        // either the id doesn't exist under this tenant OR it's
        // scoped to a different Company, both of which we surface as
        // the same 400 (not 404) so the response never leaks which
        // Company a foreign role belongs to.
        // Uses migrator_pool() for the same reason as grant_portal_access
        // above: self.db.pool() without begin_with_tenant collapses under
        // RLS to zero rows, so every role_id read as "missing" and 400'd.
        // Explicit `WHERE tenant_id = $1` is the tenant guard.
        let role_rows: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, company_id FROM portal_roles WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(*tenant_id)
        .bind(&unique)
        .fetch_all(self.db.migrator_pool())
        .await?;
        let role_map: std::collections::HashMap<Uuid, Option<Uuid>> =
            role_rows.into_iter().collect();
        for role_id in &unique {
            match role_map.get(role_id) {
                Some(role_company) => {
                    if let Some(rcid) = role_company {
                        if Some(*rcid) != contact.company_id {
                            return Err(AppError::BadRequest(format!(
                                "Role {role_id} is scoped to a different Company than the target contact"
                            )));
                        }
                    }
                }
                None => {
                    // Role missing from this tenant OR scoped to a
                    // different Company (invisible under this query).
                    // Return the same 400 shape as the scope-mismatch
                    // branch above so the response never distinguishes
                    // "does not exist" from "exists under a different
                    // Company".
                    return Err(AppError::BadRequest(format!(
                        "Role {role_id} is scoped to a different Company than the target contact"
                    )));
                }
            }
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "DELETE FROM contact_role_assignments \
             WHERE contact_id = $1 AND tenant_id = $2",
        )
        .bind(contact_id)
        .bind(*tenant_id)
        .execute(&mut *tx)
        .await?;
        for role_id in &unique {
            sqlx::query(
                "INSERT INTO contact_role_assignments (contact_id, role_id, tenant_id) \
                 VALUES ($1, $2, $3)",
            )
            .bind(contact_id)
            .bind(role_id)
            .bind(*tenant_id)
            .execute(&mut *tx)
            .await?;
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contacts",
            Some(contact_id),
            None,
            Some(serde_json::json!({
                "portal_roles_replaced": true,
                "role_ids": unique,
            })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// mokosh-contact-login prompt 010 (PMS-918): the grant email
    /// changes shape from the prompt-003 single-CTA "Set your
    /// password" to a two-block "Sign in now via magic link (primary)
    /// + Prefer a password? (secondary)" template.
    ///
    /// Both tokens are minted at grant time so the recipient can pick
    /// whichever path they prefer without a second server round-trip.
    /// The magic-link intent expires in 15 min (per the intent TTL);
    /// if not clicked, the recipient can request a fresh one via
    /// `/portal/login` or use the still-valid 72h set-password link.
    ///
    /// Best-effort dispatch: a failed send never rolls back the grant
    /// transaction (both tokens are already persisted).
    async fn send_grant_email(
        &self,
        contact: &Contact,
        portal_slug: &str,
        portal_id: i64,
        token: &str,
    ) {
        let Some(ref email) = contact.email else {
            tracing::warn!(
                contact_id = %contact.id,
                "portal access granted but contact has no email; sign-in links not delivered",
            );
            return;
        };
        let password_setup_link = format!(
            "{}/portal/{}/set-password?token={}",
            self.app_url.trim_end_matches('/'),
            portal_slug,
            token,
        );

        // Mint the magic-link intent for this contact's email so the
        // recipient can one-click into the portal without ever
        // choosing a password. Failure to mint (DB error) skips the
        // magic-link block but still dispatches the set-password
        // link, so a partially-unreachable DB does not lose the whole
        // grant email.
        let magic_link_url = match self
            .mint_grant_magic_link_url(contact.tenant_id, email)
            .await
        {
            Ok(u) => Some(u),
            Err(e) => {
                tracing::warn!(
                    contact_id = %contact.id,
                    error = ?e,
                    "failed to mint magic-link intent for grant email; falling back to password-only email",
                );
                None
            }
        };

        let Some(notify) = self.notifications.as_ref() else {
            tracing::warn!(
                contact_id = %contact.id,
                password_setup_link = %password_setup_link,
                "no notifications dispatcher wired; portal setup token persisted but no message queued (setup_link logged for manual relay)",
            );
            return;
        };
        let mut context = serde_json::json!({
            "recipient_email": email,
            "display_name": contact.first_name,
            "password_setup_link": password_setup_link,
            // mokosh-contact-login prompt 011 (PMS-928): the grant
            // email now surfaces the 9-digit Portal ID prominently so
            // the recipient can dictate it over the phone and future
            // logins (which take Portal ID + email + password) already
            // know the value.
            "portal_id": portal_id.to_string(),
        });
        if let (Some(url), Some(obj)) = (magic_link_url.as_ref(), context.as_object_mut()) {
            obj.insert(
                "magic_link_url".to_string(),
                serde_json::Value::String(url.clone()),
            );
        }
        match notify
            .dispatch(
                TenantId::from_trusted(contact.tenant_id),
                "auth.portal_grant",
                &context,
            )
            .await
        {
            Ok(_) => tracing::info!(
                contact_id = %contact.id,
                magic_link_url = ?magic_link_url,
                password_setup_link = %password_setup_link,
                "portal grant email queued"
            ),
            Err(e) => tracing::warn!(
                contact_id = %contact.id,
                error = ?e,
                "portal grant email dispatch failed; tokens persisted but links unreachable",
            ),
        }
    }

    /// mokosh-contact-login prompt 010 (PMS-918): insert a fresh
    /// `portal_login_intents` row for the granted contact's email so
    /// the grant email's primary CTA drops them straight into the
    /// portal. TTL matches `ContactAuthService::LOGIN_INTENT_TTL_MIN`
    /// (15 min).
    ///
    /// Kept as a local helper (rather than a call into
    /// `ContactAuthService`) to avoid wiring the auth service into
    /// `ContactService`; the insert shape is small and any future
    /// drift is caught by the shared test that asserts the emitted
    /// URL redeems.
    async fn mint_grant_magic_link_url(
        &self,
        tenant_id: uuid::Uuid,
        email: &str,
    ) -> AppResult<String> {
        // 15 min - matches ContactAuthService::LOGIN_INTENT_TTL_MIN.
        // A magic-link intent minted here shares the redeem path with
        // the finder-issued intents.
        const LOGIN_INTENT_TTL_MIN: i64 = 15;
        let intent_id = Uuid::new_v4();
        let secret = crate::utils::crypto::generate_token(32);
        let secret_hash = crate::utils::crypto::hash_password(&secret)?;
        let expires_at = Utc::now() + Duration::minutes(LOGIN_INTENT_TTL_MIN);
        // SAFETY (PMS-285): grant email is called post-commit from
        // `grant_portal_access` and there is no `app.current_tenant`
        // GUC set at this point (the grant tx has already committed).
        // Runs on the migrator pool; the tenant id is threaded
        // explicitly onto the row so the write lands under the right
        // tenant.
        sqlx::query(
            r#"
            INSERT INTO portal_login_intents
                (id, tenant_id, email, secret_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(intent_id)
        .bind(tenant_id)
        .bind(email)
        .bind(&secret_hash)
        .bind(expires_at)
        .execute(self.db.migrator_pool())
        .await?;
        Ok(format!(
            "{}/portal/pick?token={}.{}",
            self.app_url.trim_end_matches('/'),
            intent_id,
            secret,
        ))
    }

    /// Create a new contact
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_contact(
        &self,
        tenant_id: TenantId,
        request: &CreateContactRequest,
        ctx: &AuditCtx,
    ) -> AppResult<Contact> {
        // PMS-402: only verify a CRM company exists when one is linked. A
        // freeform or company-less contact skips the existence check.
        if let Some(company_id) = request.company_id {
            self.get_company(tenant_id, company_id).await?;
        }

        // PMS-402: the stored freeform name is mutually exclusive with the FK.
        // When company_id is set, the CRM name is authoritative (resolved via
        // the read-side join), so persist NULL; otherwise store the freeform
        // label. An empty freeform string normalizes to NULL.
        let stored_company_name: Option<&str> = if request.company_id.is_some() {
            None
        } else {
            request.company_name.as_deref().filter(|s| !s.is_empty())
        };

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
                id, tenant_id, company_id, company_name, first_name, last_name, email,
                phone, mobile, fax, title, department, contact_type,
                preferred_contact_method, timezone, custom_fields, tags, notes
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )
            "#,
        )
        .bind(contact_id)
        .bind(tenant_id)
        .bind(request.company_id)
        .bind(stored_company_name)
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
            SELECT c.id, c.tenant_id, c.company_id, COALESCE(co.name, c.company_name) AS company_name,
                   c.first_name, c.last_name, c.email,
                   c.phone, c.mobile, c.fax, c.title, c.department, c.contact_type,
                   c.is_portal_user, c.portal_user_id, c.preferred_contact_method,
                   c.timezone, c.locale, c.custom_fields, c.tags, c.notes, c.avatar_url,
                   c.status, c.created_at, c.updated_at
            FROM contacts c
            LEFT JOIN companies co
                ON co.id = c.company_id AND co.tenant_id = c.tenant_id
            WHERE c.tenant_id = $1 AND c.id = $2
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
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i32;

        // Parallel WHERE clauses so the data and count queries each get
        // correctly numbered placeholders. data has $1 tenant + $2 limit
        // + $3 offset → filter binds at $4+; count has $1 tenant only →
        // filter binds at $2+.
        // The data query joins companies (alias `co`) to resolve
        // company_name (PMS-334), so its conditions and ORDER BY are
        // qualified with the contacts alias `c` to stay unambiguous
        // (both tables expose tenant_id / status / created_at). The
        // count query has no JOIN, so its conditions stay unqualified.
        let mut data_conds = vec!["c.tenant_id = $1".to_string()];
        let mut count_conds = vec!["tenant_id = $1".to_string()];
        let mut data_idx = 4;
        let mut count_idx = 2;

        if filter.q.is_some() {
            data_conds.push(format!(
                "(c.first_name ILIKE ${idx} OR c.last_name ILIKE ${idx} OR c.email ILIKE ${idx})",
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
            data_conds.push(format!("c.company_id = ${data_idx}"));
            count_conds.push(format!("company_id = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.contact_type.is_some() {
            data_conds.push(format!("c.contact_type = ${data_idx}"));
            count_conds.push(format!("contact_type = ${count_idx}"));
            data_idx += 1;
            count_idx += 1;
        }
        if filter.status.is_some() {
            data_conds.push(format!("c.status = ${data_idx}"));
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
            SELECT c.id, c.tenant_id, c.company_id, COALESCE(co.name, c.company_name) AS company_name,
                   c.first_name, c.last_name, c.email,
                   c.phone, c.mobile, c.fax, c.title, c.department, c.contact_type,
                   c.is_portal_user, c.portal_user_id, c.preferred_contact_method,
                   c.timezone, c.locale, c.custom_fields, c.tags, c.notes, c.avatar_url,
                   c.status, c.created_at, c.updated_at
            FROM contacts c
            LEFT JOIN companies co
                ON co.id = c.company_id AND co.tenant_id = c.tenant_id
            WHERE {data_where}
            ORDER BY c.{order_by}
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

    /// PMS-583: distinct non-empty values of a free-text contact field
    /// (title / department) for this tenant, powering the free-text
    /// autocomplete on the contact form. Ranked by frequency so the values
    /// the team already uses most surface first, then alphabetically, and
    /// capped at 20. `q`, when present, is a case-insensitive substring
    /// filter. The column comes from a closed enum (`ContactSuggestField`),
    /// so it is safe to interpolate; the user-supplied `q` is always bound.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn distinct_contact_field_values(
        &self,
        tenant_id: TenantId,
        field: ContactSuggestField,
        q: Option<&str>,
    ) -> AppResult<Vec<String>> {
        let column = field.column();
        let sql = format!(
            r#"
            SELECT {column} AS value
            FROM contacts
            WHERE tenant_id = $1
              AND {column} IS NOT NULL
              AND {column} <> ''
              AND ($2::text IS NULL OR {column} ILIKE $2)
            GROUP BY {column}
            ORDER BY COUNT(*) DESC, {column} ASC
            LIMIT 20
            "#
        );

        // Bound substring pattern; an empty/whitespace `q` means "no filter".
        let pattern = q
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{s}%"));

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let values: Vec<String> = sqlx::query_scalar(&sql)
            .bind(tenant_id)
            .bind(pattern)
            .fetch_all(&mut *tx)
            .await?;

        Ok(values)
    }

    // ========================================================================
    // PMS-601: company-industry lookup CRUD. Backs the company Industry
    // combobox's suggestions; admin-managed from the Settings hub. The unique
    // (tenant_id, lower(name)) index keeps the list canonical - a duplicate
    // insert/update surfaces as 409 via the AppError From<sqlx::Error> mapping.
    // ========================================================================

    /// List this tenant's industry lookup rows (paginated, alphabetical).
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_company_industries(
        &self,
        tenant_id: TenantId,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<CompanyIndustryResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i32;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM company_industries WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        let rows: Vec<CompanyIndustryRow> = sqlx::query_as(
            "SELECT id, name, is_active FROM company_industries \
             WHERE tenant_id = $1 ORDER BY name LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *tx)
        .await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Create an industry. A duplicate name (case-insensitive) returns 409.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_company_industry(
        &self,
        tenant_id: TenantId,
        request: &UpsertCompanyIndustryRequest,
        ctx: &AuditCtx,
    ) -> AppResult<CompanyIndustryResponse> {
        let id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: CompanyIndustryRow = sqlx::query_as(
            "INSERT INTO company_industries (id, tenant_id, name, is_active) \
             VALUES ($1, $2, $3, $4) RETURNING id, name, is_active",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(request.name.trim())
        .bind(request.is_active)
        .fetch_one(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "company_industries",
            Some(id),
            None,
            Some(serde_json::json!({ "name": row.name, "is_active": row.is_active })),
        )
        .await?;
        tx.commit().await?;
        Ok(row.into())
    }

    /// Update an industry's name / active flag. 404 if not in this tenant; a
    /// duplicate name returns 409.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_company_industry(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        request: &UpsertCompanyIndustryRequest,
    ) -> AppResult<CompanyIndustryResponse> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<CompanyIndustryRow> = sqlx::query_as(
            "UPDATE company_industries SET name = $3, is_active = $4, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2 RETURNING id, name, is_active",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(request.name.trim())
        .bind(request.is_active)
        .fetch_optional(&mut *tx)
        .await?;
        let row = row.ok_or_else(|| AppError::NotFound("CompanyIndustry".to_string()))?;
        tx.commit().await?;
        Ok(row.into())
    }

    /// Delete an industry. 404 if not in this tenant.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_company_industry(&self, tenant_id: TenantId, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let res = sqlx::query("DELETE FROM company_industries WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound("CompanyIndustry".to_string()));
        }
        tx.commit().await?;
        Ok(())
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
            SELECT c.id, c.tenant_id, c.company_id, COALESCE(co.name, c.company_name) AS company_name,
                   c.first_name, c.last_name, c.email,
                   c.phone, c.mobile, c.fax, c.title, c.department, c.contact_type,
                   c.is_portal_user, c.portal_user_id, c.preferred_contact_method,
                   c.timezone, c.locale, c.custom_fields, c.tags, c.notes, c.avatar_url,
                   c.status, c.created_at, c.updated_at
            FROM contacts c
            LEFT JOIN companies co
                ON co.id = c.company_id AND co.tenant_id = c.tenant_id
            WHERE c.tenant_id = $1 AND c.company_id = $2
            ORDER BY c.contact_type, c.last_name
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

        // PMS-402: the FK and the freeform name are mutually exclusive.
        // Setting company_id makes the CRM name authoritative, so clear the
        // stored freeform name in the same statement (no bind needed, it is a
        // literal NULL). Otherwise, an explicit company_name is persisted
        // (empty string normalizes to NULL via `stored_company_name` below).
        let stored_company_name: Option<Option<&str>> = if request.company_id.is_some() {
            None
        } else {
            request
                .company_name
                .as_deref()
                .map(|s| if s.is_empty() { None } else { Some(s) })
        };

        if request.company_id.is_some() {
            updates.push(format!("company_id = ${param_idx}"));
            param_idx += 1;
            updates.push("company_name = NULL".to_string());
        } else if stored_company_name.is_some() {
            updates.push(format!("company_name = ${param_idx}"));
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
        } else if let Some(name) = stored_company_name {
            // PMS-402: bind the normalized freeform name ($param after the
            // omitted company_id). `None` here means the caller passed an
            // empty string to clear it.
            q = q.bind(name);
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

/// PMS-601: company-industry lookup row.
#[derive(sqlx::FromRow)]
struct CompanyIndustryRow {
    id: Uuid,
    name: String,
    is_active: bool,
}

impl From<CompanyIndustryRow> for CompanyIndustryResponse {
    fn from(r: CompanyIndustryRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            is_active: r.is_active,
        }
    }
}

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
    // PMS-402: nullable; None for a freeform or company-less contact.
    company_id: Option<Uuid>,
    // PMS-334 / PMS-402: resolved via COALESCE(co.name, c.company_name) in
    // the read queries, so it carries the joined CRM name when company_id is
    // set and the stored freeform value otherwise.
    company_name: Option<String>,
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
            company_name: row.company_name,
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
