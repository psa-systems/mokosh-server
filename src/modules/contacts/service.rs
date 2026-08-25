//! Contact service implementation

use crate::modules::auth::TenantId;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::notifications::NotificationsService;
use crate::utils::crypto::{generate_token, hash_password};
use crate::utils::email::salutation;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// PMS-920: the alternative every company-delete refusal ends with.
///
/// Phrased as the data change rather than as a UI gesture. The field has
/// existed since migration 004 and `UpdateCompanyRequest` already accepts it,
/// so this stays true regardless of whether a given client has caught up
/// (MAPPS-575 is the SPA half).
const ARCHIVE_INSTEAD: &str =
    "archive it instead by setting its status to Inactive, which keeps its history \
     and takes it out of your active lists";

/// Turn a `23503` on the company DELETE into a refusal that says which records
/// blocked it and what to do about them.
///
/// PMS-920: the previous message listed every table that could block and told
/// the operator to "remove them first". For half of them that is advice they
/// must not take: deleting invoices, payments, contracts or time entries to
/// tidy a client list destroys the financial and billing record the deletion
/// was refused to protect. Those two cases now read differently, and both name
/// archiving, which is what the operator almost always actually wants.
///
/// Driven off the constraint name Postgres reports rather than a pre-flight
/// count per table: it is the authority on which FK actually fired, it costs no
/// extra queries, and a table added later cannot silently fall out of a
/// hand-maintained list - it lands on the generic arm instead.
fn company_delete_blocked(constraint: Option<&str>) -> AppError {
    // Records that exist to be kept. Removing them to enable a delete is worse
    // than not deleting.
    const RETAINED: &[(&str, &str)] = &[
        ("invoices_company_id_fkey", "invoices"),
        ("payments_company_id_fkey", "payments"),
        ("contracts_company_id_fkey", "contracts"),
        ("time_entries_company_id_fkey", "time entries"),
        ("mileage_entries_company_id_fkey", "mileage entries"),
    ];
    // Records the operator can legitimately clear or reassign first.
    const REMOVABLE: &[(&str, &str)] = &[
        ("assets_company_id_fkey", "assets"),
        ("quotes_company_id_fkey", "quotes"),
        ("credential_vault_company_id_fkey", "stored credentials"),
    ];

    let named = constraint.and_then(|c| {
        RETAINED
            .iter()
            .find(|(fk, _)| *fk == c)
            .map(|(_, label)| (*label, true))
            .or_else(|| {
                REMOVABLE
                    .iter()
                    .find(|(fk, _)| *fk == c)
                    .map(|(_, label)| (*label, false))
            })
    });

    let message = match named {
        Some((label, true)) => format!(
            "Cannot delete company: it has {label}, which are kept as a permanent \
             financial and billing record and must not be removed to allow a \
             deletion. You can {ARCHIVE_INSTEAD}"
        ),
        Some((label, false)) => format!(
            "Cannot delete company: it has {label}. Remove or reassign them first, \
             or {ARCHIVE_INSTEAD}"
        ),
        // An FK this function has not been taught about. Say so plainly rather
        // than guessing which half it belongs to; the alternative still holds.
        None => format!(
            "Cannot delete company: other records still reference it. Remove or \
             reassign whatever can be moved, or {ARCHIVE_INSTEAD}"
        ),
    };
    AppError::BadRequest(message)
}

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
                -- PMS-806: count through the link table so a contact linked to
                -- this company as a secondary shows up, and one holding several
                -- links to it (impossible today, UNIQUE) is still counted once.
                (SELECT COUNT(DISTINCT cc.contact_id) FROM contact_companies cc
                    WHERE cc.tenant_id = c.tenant_id
                      AND cc.company_id = c.id) AS contact_count,
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
        let order_by = pagination.order_by("name", mokosh_types::sort::COMPANIES)?;

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

        // PMS-919: the tenant's own company is refused here rather than by its
        // foreign key, because the FK is the wrong messenger twice over. It is
        // nullable, so it does not block on a fresh tenant at all: the delete
        // would succeed, `own_company_id` would go NULL, and the failure would
        // surface later as a NOT NULL violation on `time_entries` the next time
        // someone logged overhead time (PMS-413 makes this the anchor for that,
        // and MAPPS-243 sends it as the company). On a tenant that already has
        // overhead time it blocks, but as a generic related-records error
        // naming `time_entries`, which does not tell the operator that the real
        // problem is the company's role. Checked first because it is a
        // statement about what this company IS, not about what references it.
        let is_own_company: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1 AND own_company_id = $2)",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(&mut *tx)
        .await?;

        if is_own_company {
            return Err(AppError::BadRequest(
                "This is your organisation's own company record, which general and \
                 overhead time is logged against; it cannot be deleted"
                    .to_string(),
            ));
        }

        // Check for related records
        let ticket_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND company_id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(&mut *tx)
        .await?;

        if ticket_count > 0 {
            // PMS-920: tickets are removable, so "delete them first" is advice
            // the operator can actually take, but it is rarely the one they
            // want. Name the alternative alongside it.
            return Err(AppError::BadRequest(format!(
                "Cannot delete company: it has {ticket_count} ticket(s). Delete or \
                 reassign them first, or {ARCHIVE_INSTEAD}"
            )));
        }

        let before: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM companies c WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;

        // PMS-812: unlink this company's contacts, never delete them. Runs
        // BEFORE the company DELETE so `recompute_contact_mirrors` - the single
        // writer of `contacts.company_id` (PMS-806) - leaves no mirror pointing
        // at the row that is about to go. The `ON DELETE SET NULL` action added
        // in migration 110 is only the backstop for a direct SQL delete.
        let unlinked: Vec<Uuid> = sqlx::query_scalar(
            "DELETE FROM contact_companies WHERE tenant_id = $1 AND company_id = $2 \
             RETURNING contact_id",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;

        if !unlinked.is_empty() {
            // Same promotion rule as `write_contact_companies`: a contact that
            // just lost its primary gets its OLDEST remaining link, ordered by
            // `(created_at, sort_order, id)` (PMS-815). `DISTINCT ON` picks one
            // row per contact and the `NOT EXISTS` skips contacts that still
            // have a primary, so the partial unique index cannot collide.
            sqlx::query(
                r#"
                UPDATE contact_companies l
                SET is_primary = TRUE, updated_at = NOW()
                FROM (
                    SELECT DISTINCT ON (contact_id) id, contact_id
                    FROM contact_companies
                    WHERE tenant_id = $1 AND contact_id = ANY($2)
                    ORDER BY contact_id, created_at, sort_order, id
                ) oldest
                WHERE l.id = oldest.id
                  AND NOT EXISTS (
                      SELECT 1 FROM contact_companies p
                      WHERE p.contact_id = oldest.contact_id AND p.is_primary
                  )
                "#,
            )
            .bind(tenant_id)
            .bind(&unlinked)
            .execute(&mut *tx)
            .await?;

            for contact_id in &unlinked {
                self.recompute_contact_mirrors(&mut tx, tenant_id, *contact_id)
                    .await?;
            }
        }

        // The explicit ticket guard above only covers one of the tables that
        // foreign-key `companies`. The rest still default to NO ACTION, so the
        // DELETE raises Postgres `23503`; map it to a 400 instead of letting
        // the generic `From<sqlx::Error>` turn it into a 500 (PMS-170, same
        // shape as the PMS-149 ticket-delete fix).
        //
        // PMS-919 narrowed which tables can reach this. `projects`,
        // `appointments`, `active_timers`, `rmm_device_mappings` and
        // `parent_company_id` are nullable and now `ON DELETE SET NULL`
        // (migration 113), so they unlink rather than block and must not be
        // named. What is left is the `NOT NULL` group, where a company-less row
        // is not a valid state, plus `credential_vault`, which is nullable but
        // keeps blocking on purpose: nulling it would leave encrypted secrets
        // owned by nothing and cascading would destroy them silently.
        if let Err(e) = sqlx::query("DELETE FROM companies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(company_id)
            .execute(&mut *tx)
            .await
        {
            let db_err = e.as_database_error();
            if db_err.and_then(|d| d.code()).as_deref() == Some("23503") {
                return Err(company_delete_blocked(
                    db_err.and_then(|d| d.constraint()),
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
    /// PMS-700: queued through the `auth.welcome` dispatch rather than sent
    /// inline, so the contact gets the same rendered template (and the same
    /// worker retries) as the staff welcome mail.
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
        let Some(notify) = self.notifications.as_ref() else {
            tracing::warn!(
                contact_id = %contact.id,
                "no notifications dispatcher wired; portal setup token persisted but no message queued",
            );
            return;
        };
        let context = serde_json::json!({
            "recipient_email": email,
            // PMS-774: `contacts.first_name` is NOT NULL but may hold an empty
            // string, so the greeting word comes from `salutation` rather than
            // from the name. `display_name` stays the bare name so a customised
            // tenant template that names it keeps rendering.
            "salutation": salutation(&contact.first_name),
            "display_name": contact.first_name,
            "setup_link": setup_link,
        });
        // SAFETY (PMS-261): `contact.tenant_id` is read off the contact row
        // this method was handed, not from caller input; `dispatch` re-derives
        // the RLS GUC per query via `begin_with_tenant`.
        match notify
            .dispatch(
                TenantId::from_trusted(contact.tenant_id),
                "auth.welcome",
                &context,
            )
            .await
        {
            Ok(_) => tracing::info!(contact_id = %contact.id, "portal setup-link email queued"),
            Err(e) => tracing::warn!(
                contact_id = %contact.id,
                error = ?e,
                "portal setup email dispatch failed; token persisted but link unreachable",
            ),
        }
    }

    // ------------------------------------------------------------------
    // PMS-806: contact child collections (`contact_phones`,
    // `contact_companies`) and the mirror columns derived from them.
    // ------------------------------------------------------------------

    /// Reject any `company_id` in a link list that does not belong to this
    /// tenant. Runs BEFORE the write transaction opens, so a foreign id never
    /// reaches an INSERT.
    async fn validate_company_links(
        &self,
        tenant_id: TenantId,
        links: &[ContactCompanyLinkInput],
    ) -> AppResult<()> {
        for link in links {
            self.validate_fk(tenant_id, "companies", link.company_id)
                .await?;
        }
        Ok(())
    }

    /// Replace a contact's phone rows with `phones`, in list order.
    ///
    /// Phone entries carry no stable natural key, so the list is rewritten
    /// wholesale and `contact_phones.id` is not stable across writes. The
    /// partial unique index allows one primary row per contact; deleting the
    /// old rows first is what keeps a primary swap from colliding with it.
    async fn write_contact_phones(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
        phones: &[ResolvedPhone],
    ) -> AppResult<()> {
        sqlx::query("DELETE FROM contact_phones WHERE tenant_id = $1 AND contact_id = $2")
            .bind(tenant_id)
            .bind(contact_id)
            .execute(&mut *conn)
            .await?;
        for phone in phones {
            sqlx::query(
                r#"
                INSERT INTO contact_phones
                    (tenant_id, contact_id, phone_type, number, extension, is_primary, sort_order)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(tenant_id)
            .bind(contact_id)
            .bind(phone.phone_type.as_str())
            .bind(&phone.number)
            .bind(&phone.extension)
            .bind(phone.is_primary)
            .bind(phone.sort_order)
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }

    /// Replace a contact's company links with `links`.
    ///
    /// Unlike phones, a link HAS a natural key (`contact_id, company_id`), so
    /// surviving links are upserted rather than recreated and keep their
    /// `created_at`. That is what makes "promote the oldest remaining link"
    /// meaningful after the primary link is removed.
    ///
    /// Which link ends up primary, in order:
    ///
    /// 1. the one the caller flagged (two flagged is a 422 at the request layer);
    /// 2. else the OLDEST link that already existed and survives this write, so
    ///    removing the primary promotes the oldest remaining link and an
    ///    unflagged rewrite does not silently reshuffle the primary;
    /// 3. else the first entry in the list, which is the create case (nothing
    ///    pre-existed) and the "promote the first entry" rule.
    ///
    /// "Oldest" is `(created_at, sort_order)`, not `created_at` alone: NOW() is
    /// the transaction timestamp, so every link written by one call shares one
    /// `created_at` and only `sort_order` separates them (PMS-815). It is set
    /// on INSERT and left alone on conflict, so a surviving link keeps its
    /// original position.
    async fn write_contact_companies(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
        links: &[ResolvedLink],
    ) -> AppResult<()> {
        let existing_order: Vec<Uuid> = sqlx::query_scalar(
            "SELECT company_id FROM contact_companies \
             WHERE tenant_id = $1 AND contact_id = $2 \
             ORDER BY created_at, sort_order, id",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut *conn)
        .await?;

        let keep: Vec<Uuid> = links.iter().map(|l| l.company_id).collect();
        sqlx::query(
            "DELETE FROM contact_companies \
             WHERE tenant_id = $1 AND contact_id = $2 AND NOT (company_id = ANY($3))",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(&keep)
        .execute(&mut *conn)
        .await?;

        // Every row lands non-primary first. The partial unique index permits
        // one primary per contact, so promoting before demoting would collide;
        // a single promotion at the end sidesteps the ordering entirely.
        sqlx::query(
            "UPDATE contact_companies SET is_primary = FALSE \
             WHERE tenant_id = $1 AND contact_id = $2 AND is_primary",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .execute(&mut *conn)
        .await?;

        for (position, link) in links.iter().enumerate() {
            sqlx::query(
                r#"
                INSERT INTO contact_companies
                    (tenant_id, contact_id, company_id, title, is_primary, sort_order)
                VALUES ($1, $2, $3, $4, FALSE, $5)
                ON CONFLICT (contact_id, company_id) DO UPDATE
                    SET title = EXCLUDED.title,
                        updated_at = NOW()
                "#,
            )
            .bind(tenant_id)
            .bind(contact_id)
            .bind(link.company_id)
            .bind(&link.title)
            .bind(position as i32)
            .execute(&mut *conn)
            .await?;
        }

        let primary = links
            .iter()
            .find(|l| l.is_primary)
            .map(|l| l.company_id)
            .or_else(|| existing_order.iter().copied().find(|id| keep.contains(id)))
            .or_else(|| links.first().map(|l| l.company_id));
        if let Some(primary) = primary {
            sqlx::query(
                "UPDATE contact_companies SET is_primary = TRUE, updated_at = NOW() \
                 WHERE tenant_id = $1 AND contact_id = $2 AND company_id = $3",
            )
            .bind(tenant_id)
            .bind(contact_id)
            .bind(primary)
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }

    /// THE one place that writes the derived `contacts` columns (PMS-806).
    ///
    /// `phone` / `mobile` / `fax` / `company_id` are maintained mirrors of the
    /// child tables, kept so every pre-PMS-806 query, index, seed fixture,
    /// portal lookup and the current SPA keep working unchanged. Every create
    /// and update calls this inside its own transaction, right after writing
    /// the child rows.
    ///
    /// `company_name` (the freeform label) is cleared whenever a primary link
    /// exists: the two are mutually exclusive (PMS-402), and the read side
    /// resolves `COALESCE(co.name, c.company_name)` anyway.
    async fn recompute_contact_mirrors(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            UPDATE contacts c SET
                phone = (
                    SELECT p.number FROM contact_phones p
                    WHERE p.contact_id = c.id AND p.is_primary
                    ORDER BY p.sort_order, p.created_at LIMIT 1
                ),
                mobile = (
                    SELECT p.number FROM contact_phones p
                    WHERE p.contact_id = c.id AND p.phone_type = 'mobile'
                    ORDER BY p.sort_order, p.created_at LIMIT 1
                ),
                fax = (
                    SELECT p.number FROM contact_phones p
                    WHERE p.contact_id = c.id AND p.phone_type = 'fax'
                    ORDER BY p.sort_order, p.created_at LIMIT 1
                ),
                company_id = (
                    SELECT l.company_id FROM contact_companies l
                    WHERE l.contact_id = c.id AND l.is_primary LIMIT 1
                ),
                company_name = CASE
                    WHEN EXISTS (
                        SELECT 1 FROM contact_companies l
                        WHERE l.contact_id = c.id AND l.is_primary
                    ) THEN NULL
                    ELSE c.company_name
                END,
                updated_at = NOW()
            WHERE c.tenant_id = $1 AND c.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// Load `phones` and `companies` for a page of contacts with ONE query per
    /// child table, then attach them. No per-row query: `list_contacts` and
    /// `get_company_contacts` both hydrate a whole page this way.
    async fn hydrate_contacts(
        &self,
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        rows: Vec<ContactRow>,
    ) -> AppResult<Vec<Contact>> {
        let mut contacts: Vec<Contact> = rows.into_iter().map(Into::into).collect();
        if contacts.is_empty() {
            return Ok(contacts);
        }
        let ids: Vec<Uuid> = contacts.iter().map(|c| c.id).collect();

        let phone_rows = sqlx::query_as::<_, ContactPhoneRow>(
            r#"
            SELECT id, contact_id, phone_type, number, extension, is_primary, sort_order
            FROM contact_phones
            WHERE tenant_id = $1 AND contact_id = ANY($2)
            ORDER BY contact_id, sort_order, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?;

        let link_rows = sqlx::query_as::<_, ContactCompanyLinkRow>(
            r#"
            SELECT l.contact_id, l.company_id, co.name AS company_name, l.title, l.is_primary
            FROM contact_companies l
            LEFT JOIN companies co ON co.id = l.company_id AND co.tenant_id = l.tenant_id
            WHERE l.tenant_id = $1 AND l.contact_id = ANY($2)
            ORDER BY l.contact_id, l.is_primary DESC, l.created_at, l.sort_order, l.id
            "#,
        )
        .bind(tenant_id)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?;

        let mut phones_by_contact: std::collections::HashMap<Uuid, Vec<ContactPhone>> =
            std::collections::HashMap::new();
        for row in phone_rows {
            phones_by_contact
                .entry(row.contact_id)
                .or_default()
                .push(ContactPhone {
                    id: row.id,
                    // The column's CHECK constrains it to exactly the enum's
                    // five values, so the fallback is unreachable; it matches
                    // the `contact_type` / `status` handling above.
                    phone_type: PhoneType::from_str(&row.phone_type).unwrap_or_default(),
                    number: row.number,
                    extension: row.extension,
                    is_primary: row.is_primary,
                    sort_order: row.sort_order,
                });
        }
        let mut links_by_contact: std::collections::HashMap<Uuid, Vec<ContactCompanyLink>> =
            std::collections::HashMap::new();
        for row in link_rows {
            links_by_contact
                .entry(row.contact_id)
                .or_default()
                .push(ContactCompanyLink {
                    company_id: row.company_id,
                    company_name: row.company_name,
                    title: row.title,
                    is_primary: row.is_primary,
                });
        }

        for contact in contacts.iter_mut() {
            contact.phones = phones_by_contact.remove(&contact.id).unwrap_or_default();
            contact.companies = links_by_contact.remove(&contact.id).unwrap_or_default();
        }
        Ok(contacts)
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
        // PMS-806: every company named in the list is checked against this
        // tenant before any row is written.
        if let Some(links) = request.companies.as_deref() {
            self.validate_company_links(tenant_id, links).await?;
        }

        // PMS-806: an explicit list is authoritative and the matching scalars
        // in the same request are ignored; an absent list is materialized from
        // those scalars, which is what keeps a pre-PMS-806 request creating
        // exactly the same contact.
        let phones = match request.phones.as_deref() {
            Some(entries) => resolve_phone_list(entries)?,
            None => phones_from_scalars(
                request.phone.as_deref(),
                request.mobile.as_deref(),
                request.fax.as_deref(),
            ),
        };
        let links = match request.companies.as_deref() {
            Some(entries) => resolve_company_list(entries),
            None => request
                .company_id
                .map(|company_id| ResolvedLink {
                    company_id,
                    title: request.title.clone(),
                    is_primary: true,
                })
                .into_iter()
                .collect(),
        };

        // PMS-402: the stored freeform name is mutually exclusive with the FK.
        // When company_id is set, the CRM name is authoritative (resolved via
        // the read-side join), so persist NULL; otherwise store the freeform
        // label. An empty freeform string normalizes to NULL. PMS-806: a
        // non-empty `companies` list makes a CRM name authoritative the same
        // way (the request layer already rejects both at once).
        let stored_company_name: Option<&str> = if request.company_id.is_some() || !links.is_empty()
        {
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

        // PMS-806: the child collections are authoritative; the scalar columns
        // written above are then recomputed from them in the same transaction,
        // so the audit `after` snapshot below already shows the mirrors.
        self.write_contact_phones(&mut tx, tenant_id, contact_id, &phones)
            .await?;
        self.write_contact_companies(&mut tx, tenant_id, contact_id, &links)
            .await?;
        self.recompute_contact_mirrors(&mut tx, tenant_id, contact_id)
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

        let mut contacts = self.hydrate_contacts(&mut tx, tenant_id, vec![row]).await?;
        contacts
            .pop()
            .ok_or_else(|| AppError::NotFound("Contact".to_string()))
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
            // PMS-806: match through ANY link, not just the primary one that
            // `contacts.company_id` mirrors. `contacts` is aliased `c` in the
            // data query and unaliased in the count query, hence the two forms.
            data_conds.push(format!(
                "EXISTS (SELECT 1 FROM contact_companies cc \
                 WHERE cc.tenant_id = c.tenant_id AND cc.contact_id = c.id \
                   AND cc.company_id = ${data_idx})"
            ));
            count_conds.push(format!(
                "EXISTS (SELECT 1 FROM contact_companies cc \
                 WHERE cc.tenant_id = contacts.tenant_id AND cc.contact_id = contacts.id \
                   AND cc.company_id = ${count_idx})"
            ));
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
        let order_by = pagination.order_by("last_name", mokosh_types::sort::CONTACTS)?;

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
        // PMS-806: two more queries for the whole page, not one per row.
        let contacts = self.hydrate_contacts(&mut tx, tenant_id, rows).await?;

        Ok((contacts, total as u64))
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
        let row = row.ok_or_else(|| AppError::NotFound("Company industry".to_string()))?;
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
            return Err(AppError::NotFound("Company industry".to_string()));
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
        // PMS-806: a contact belongs to this company through ANY of its links,
        // not only the primary one that `contacts.company_id` mirrors. The
        // EXISTS counts each contact once however many links it holds.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM contacts c \
             WHERE c.tenant_id = $1 AND EXISTS ( \
                 SELECT 1 FROM contact_companies cc \
                 WHERE cc.tenant_id = c.tenant_id AND cc.contact_id = c.id \
                   AND cc.company_id = $2)",
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
            WHERE c.tenant_id = $1 AND EXISTS (
                SELECT 1 FROM contact_companies cc
                WHERE cc.tenant_id = c.tenant_id AND cc.contact_id = c.id
                  AND cc.company_id = $2
            )
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
        // PMS-806: batched hydration, one query per child table for the page.
        let contacts = self.hydrate_contacts(&mut tx, tenant_id, rows).await?;

        Ok((contacts, total as u64))
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
        let existing = self.get_contact(tenant_id, contact_id).await?;

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
        // PMS-806: same check for every company named in the link list, before
        // any row is written.
        if let Some(links) = request.companies.as_deref() {
            self.validate_company_links(tenant_id, links).await?;
        }

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

        // PMS-806: rewrite the child collections, then recompute the mirrors
        // from them in this same transaction.
        //
        // An explicit list is authoritative. With no list, a request that
        // touches any scalar phone field rebuilds the list from the resulting
        // scalars, and a request that sets `company_id` makes that company the
        // contact's only link: both preserve the pre-PMS-806 semantics the
        // current SPA relies on. A request that touches neither leaves the
        // child rows exactly as they are.
        let phones = match request.phones.as_deref() {
            Some(entries) => Some(resolve_phone_list(entries)?),
            None if request.phone.is_some()
                || request.mobile.is_some()
                || request.fax.is_some() =>
            {
                Some(phones_from_scalars(
                    request.phone.as_deref().or(existing.phone.as_deref()),
                    request.mobile.as_deref().or(existing.mobile.as_deref()),
                    request.fax.as_deref().or(existing.fax.as_deref()),
                ))
            }
            None => None,
        };
        let links = match request.companies.as_deref() {
            Some(entries) => Some(resolve_company_list(entries)),
            None => request.company_id.map(|company_id| {
                vec![ResolvedLink {
                    company_id,
                    title: request.title.clone().or_else(|| existing.title.clone()),
                    is_primary: true,
                }]
            }),
        };
        if let Some(ref phones) = phones {
            self.write_contact_phones(&mut tx, tenant_id, contact_id, phones)
                .await?;
        }
        if let Some(ref links) = links {
            self.write_contact_companies(&mut tx, tenant_id, contact_id, links)
                .await?;
        }
        // Unconditional: the mirrors are derived state, so re-deriving them is
        // idempotent when nothing changed and self-healing when it did.
        self.recompute_contact_mirrors(&mut tx, tenant_id, contact_id)
            .await?;

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
            // PMS-806: filled by `hydrate_contacts` in one batched query per
            // child table; a bare row conversion leaves them empty.
            phones: Vec::new(),
            companies: Vec::new(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

// ============================================================================
// PMS-806: request -> child-row resolution
// ============================================================================

/// A phone entry resolved from a request, ready to write to `contact_phones`.
struct ResolvedPhone {
    phone_type: PhoneType,
    number: String,
    extension: Option<String>,
    is_primary: bool,
    sort_order: i32,
}

/// A company link resolved from a request, ready to write to
/// `contact_companies`.
struct ResolvedLink {
    company_id: Uuid,
    title: Option<String>,
    is_primary: bool,
}

/// Resolve an explicit `phones` list. The array order IS the sort order. A list
/// with no entry flagged primary promotes the first entry rather than erroring;
/// two flagged entries were already rejected as a 422 at the request layer.
///
/// `number` is `Option<String>` because it carries the shared `de_phone_opt`
/// normalization (a blank number deserializes to `None`); the request-layer
/// `required` rule rejects `None`, and this is the fail-loud backstop for a
/// caller that reaches the service without validating.
fn resolve_phone_list(entries: &[ContactPhoneInput]) -> AppResult<Vec<ResolvedPhone>> {
    let mut resolved = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let number = entry.number.clone().ok_or_else(|| {
            AppError::validation_field(
                format!("phones[{index}].number"),
                "a phone number is required",
            )
        })?;
        resolved.push(ResolvedPhone {
            phone_type: entry.phone_type,
            number,
            extension: entry.extension.clone(),
            is_primary: entry.is_primary,
            sort_order: index as i32,
        });
    }
    if !resolved.is_empty() && !resolved.iter().any(|p| p.is_primary) {
        resolved[0].is_primary = true;
    }
    Ok(resolved)
}

/// Materialize the child rows implied by the legacy scalar fields, so a
/// pre-PMS-806 request still ends up with a populated `contact_phones`.
///
/// Only the `phone` scalar becomes the primary entry. That is deliberate: if a
/// contact carries a mobile but no `phone`, promoting the mobile would make the
/// mirror rule write that number back into `contacts.phone`, changing what an
/// unchanged request stores today. The migration backfill uses the same rule.
fn phones_from_scalars(
    phone: Option<&str>,
    mobile: Option<&str>,
    fax: Option<&str>,
) -> Vec<ResolvedPhone> {
    let mut resolved = Vec::new();
    if let Some(number) = phone.filter(|s| !s.is_empty()) {
        resolved.push(ResolvedPhone {
            phone_type: PhoneType::Work,
            number: number.to_string(),
            extension: None,
            is_primary: true,
            sort_order: 0,
        });
    }
    if let Some(number) = mobile.filter(|s| !s.is_empty()) {
        resolved.push(ResolvedPhone {
            phone_type: PhoneType::Mobile,
            number: number.to_string(),
            extension: None,
            is_primary: false,
            sort_order: 1,
        });
    }
    if let Some(number) = fax.filter(|s| !s.is_empty()) {
        resolved.push(ResolvedPhone {
            phone_type: PhoneType::Fax,
            number: number.to_string(),
            extension: None,
            is_primary: false,
            sort_order: 2,
        });
    }
    resolved
}

/// Resolve an explicit `companies` list, preserving the caller's flags as-is.
/// Which link ends up primary when none is flagged is decided by
/// [`ContactService::write_contact_companies`], because it depends on which
/// links already existed. Duplicate ids and two primaries are 422s at the
/// request layer.
fn resolve_company_list(entries: &[ContactCompanyLinkInput]) -> Vec<ResolvedLink> {
    entries
        .iter()
        .map(|e| ResolvedLink {
            company_id: e.company_id,
            title: e.title.clone(),
            is_primary: e.is_primary,
        })
        .collect()
}

#[derive(sqlx::FromRow)]
struct ContactPhoneRow {
    id: Uuid,
    contact_id: Uuid,
    phone_type: String,
    number: String,
    extension: Option<String>,
    is_primary: bool,
    sort_order: i32,
}

#[derive(sqlx::FromRow)]
struct ContactCompanyLinkRow {
    contact_id: Uuid,
    company_id: Uuid,
    company_name: Option<String>,
    title: Option<String>,
    is_primary: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    // These live in the server crate, not `mokosh-types`, because `cargo test
    // --lib` (the pre-commit and check.yml gate) only builds the root package's
    // lib target. The `mokosh-types` test target does not compile today, which
    // is tracked separately; mirroring the PMS-806 rules here means they are
    // actually enforced on every run.

    fn contact_req(body: serde_json::Value) -> CreateContactRequest {
        let mut full = serde_json::json!({ "first_name": "Ada", "last_name": "Lovelace" });
        if let serde_json::Value::Object(extra) = body {
            for (k, v) in extra {
                full[k] = v;
            }
        }
        serde_json::from_value(full).expect("contact request deserializes")
    }

    #[test]
    fn phone_type_round_trips_through_serde_and_the_db_strings() {
        for (variant, wire) in [
            (PhoneType::Mobile, "mobile"),
            (PhoneType::Work, "work"),
            (PhoneType::Home, "home"),
            (PhoneType::Fax, "fax"),
            (PhoneType::Other, "other"),
        ] {
            let json = serde_json::to_string(&variant).expect("serializes");
            assert_eq!(json, format!("\"{wire}\""));
            assert_eq!(
                serde_json::from_str::<PhoneType>(&json).expect("deserializes"),
                variant
            );
            // Same strings back the `contact_phones.phone_type` CHECK.
            assert_eq!(variant.as_str(), wire);
            assert_eq!(PhoneType::from_str(wire), Some(variant));
        }
        assert_eq!(PhoneType::from_str("pager"), None);
        assert_eq!(PhoneType::default(), PhoneType::Other);
    }

    #[test]
    fn phone_list_uses_array_order_and_promotes_the_first_entry() {
        let req = contact_req(serde_json::json!({
            "phones": [
                { "phone_type": "work", "number": "+1 (415) 555-1234" },
                { "phone_type": "mobile", "number": "+14155559999" },
            ],
        }));
        assert!(req.validate().is_ok());
        let resolved =
            resolve_phone_list(req.phones.as_deref().expect("phones")).expect("resolves");
        assert_eq!(resolved.len(), 2);
        // de_phone_opt normalization reaches the child row, not just the scalar.
        assert_eq!(resolved[0].number, "+14155551234");
        assert!(resolved[0].is_primary, "first entry is promoted");
        assert_eq!(resolved[0].sort_order, 0);
        assert!(!resolved[1].is_primary);
        assert_eq!(resolved[1].sort_order, 1);
    }

    #[test]
    fn explicit_primary_phone_is_respected() {
        let req = contact_req(serde_json::json!({
            "phones": [
                { "phone_type": "work", "number": "+14155551234" },
                { "phone_type": "mobile", "number": "+14155559999", "is_primary": true },
            ],
        }));
        let resolved =
            resolve_phone_list(req.phones.as_deref().expect("phones")).expect("resolves");
        assert!(!resolved[0].is_primary);
        assert!(resolved[1].is_primary);
    }

    #[test]
    fn two_primary_entries_are_rejected_before_the_service() {
        let phones = contact_req(serde_json::json!({
            "phones": [
                { "phone_type": "work", "number": "+14155551234", "is_primary": true },
                { "phone_type": "home", "number": "+14155555678", "is_primary": true },
            ],
        }));
        assert!(phones.validate().is_err());

        let companies = contact_req(serde_json::json!({
            "companies": [
                { "company_id": "11111111-1111-1111-1111-111111111111", "is_primary": true },
                { "company_id": "22222222-2222-2222-2222-222222222222", "is_primary": true },
            ],
        }));
        assert!(companies.validate().is_err());
    }

    #[test]
    fn invalid_phone_entry_is_a_422_naming_the_entry() {
        let req = contact_req(serde_json::json!({
            "phones": [
                { "phone_type": "work", "number": "+14155551234" },
                { "phone_type": "home", "number": "not-a-phone" },
            ],
        }));
        let err: AppError = req.validate().expect_err("invalid entry rejected").into();
        assert_eq!(err.status_code(), 422);
        let AppError::Validation { ref errors, .. } = err else {
            panic!("expected a validation error, got {err:?}");
        };
        assert!(
            errors.iter().any(|f| f.field == "phones[1].number"),
            "the 422 must name the failing entry, got {errors:?}"
        );
    }

    #[test]
    fn a_phone_entry_with_no_number_fails_loud_in_the_service_too() {
        // The request layer rejects this first; the service must not silently
        // substitute an empty number if it is ever reached directly.
        let entries: Vec<ContactPhoneInput> =
            serde_json::from_value(serde_json::json!([{ "phone_type": "work", "number": null }]))
                .expect("entries deserialize");
        let err = resolve_phone_list(&entries)
            .err()
            .expect("a missing number is an error");
        assert_eq!(err.status_code(), 422);
    }

    #[test]
    fn companies_list_with_a_freeform_name_is_rejected() {
        let req = contact_req(serde_json::json!({
            "company_name": "Acme Plumbing",
            "companies": [{ "company_id": "11111111-1111-1111-1111-111111111111" }],
        }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn duplicate_company_links_are_rejected_before_the_unique_constraint() {
        let req = contact_req(serde_json::json!({
            "companies": [
                { "company_id": "11111111-1111-1111-1111-111111111111" },
                { "company_id": "11111111-1111-1111-1111-111111111111" },
            ],
        }));
        assert!(req.validate().is_err());
    }

    #[test]
    fn company_list_resolution_preserves_the_callers_flags() {
        // Which link becomes primary when none is flagged depends on which
        // links already exist, so `write_contact_companies` decides it; the
        // resolver must not pre-empt that (integration coverage:
        // `a_list_with_no_primary_promotes_the_first_entry` and
        // `removing_links_repromotes_and_recomputes`).
        let req = contact_req(serde_json::json!({
            "companies": [
                { "company_id": "11111111-1111-1111-1111-111111111111" },
                { "company_id": "22222222-2222-2222-2222-222222222222", "is_primary": true },
            ],
        }));
        let resolved = resolve_company_list(req.companies.as_deref().expect("companies"));
        assert!(!resolved[0].is_primary);
        assert!(resolved[1].is_primary);

        let unflagged = contact_req(serde_json::json!({
            "companies": [{ "company_id": "11111111-1111-1111-1111-111111111111" }],
        }));
        let resolved = resolve_company_list(unflagged.companies.as_deref().expect("companies"));
        assert!(!resolved[0].is_primary);
    }

    #[test]
    fn scalars_materialize_child_rows_without_changing_the_mirror() {
        // Only `phone` is primary: promoting a lone mobile would make the
        // mirror rule write it back into `contacts.phone`, which a pre-PMS-806
        // request never did.
        let resolved = phones_from_scalars(Some("+14155551234"), Some("+14155559999"), None);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].phone_type, PhoneType::Work);
        assert!(resolved[0].is_primary);
        assert_eq!(resolved[1].phone_type, PhoneType::Mobile);
        assert!(!resolved[1].is_primary);

        let mobile_only = phones_from_scalars(None, Some("+14155559999"), None);
        assert_eq!(mobile_only.len(), 1);
        assert!(
            !mobile_only[0].is_primary,
            "a mobile-only contact keeps contacts.phone NULL"
        );

        assert!(phones_from_scalars(None, None, None).is_empty());
    }
}
