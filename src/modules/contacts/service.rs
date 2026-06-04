//! Contact service implementation

use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Contact management service
#[derive(Clone)]
pub struct ContactService {
    db: Database,
}

impl ContactService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Reject a foreign id that does not belong to this tenant, so a request
    /// body cannot link a row to another tenant's data. `table` is a
    /// compile-time constant, never user input.
    async fn validate_fk(&self, tenant_id: Uuid, table: &'static str, id: Uuid) -> AppResult<()> {
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE tenant_id = $1 AND id = $2)"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_one(self.db.pool())
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
        tenant_id: Uuid,
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
        tenant_id: Uuid,
        request: &CreateCompanyRequest,
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
        .execute(self.db.pool())
        .await?;

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
        tenant_id: Uuid,
        mut responses: Vec<CompanyResponse>,
    ) -> AppResult<Vec<CompanyResponse>> {
        if responses.is_empty() {
            return Ok(responses);
        }
        let ids: Vec<Uuid> = responses.iter().map(|r| r.id).collect();
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
        .fetch_all(self.db.pool())
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
    pub async fn get_company(&self, tenant_id: Uuid, company_id: Uuid) -> AppResult<Company> {
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
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Company".to_string()))?;

        Ok(row.into())
    }

    /// List companies with filters
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_companies(
        &self,
        tenant_id: Uuid,
        filter: &CompanyFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Company>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        // Build dynamic query
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 4;

        if filter.q.is_some() {
            conditions.push(format!("name ILIKE ${}", param_idx));
            param_idx += 1;
        }
        if filter.company_type.is_some() {
            conditions.push(format!("company_type = ${}", param_idx));
            param_idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${}", param_idx));
            param_idx += 1;
        }
        if filter.account_manager_id.is_some() {
            conditions.push(format!("account_manager_id = ${}", param_idx));
            // param_idx += 1;
        }

        let where_clause = conditions.join(" AND ");
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
            WHERE {}
            ORDER BY {}
            LIMIT $2 OFFSET $3
            "#,
            where_clause, order_by
        );

        let count_query = format!("SELECT COUNT(*) FROM companies WHERE {}", where_clause);

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

        let rows = query_builder.fetch_all(self.db.pool()).await?;
        let total = count_builder.fetch_one(self.db.pool()).await?;

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
        tenant_id: Uuid,
        company_id: Uuid,
        request: &UpdateCompanyRequest,
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

        // Build update query dynamically
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if request.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if request.company_type.is_some() {
            updates.push(format!("company_type = ${}", param_idx));
            param_idx += 1;
        }
        if request.status.is_some() {
            updates.push(format!("status = ${}", param_idx));
            param_idx += 1;
        }
        // Add more fields as needed...

        let query = format!(
            "UPDATE companies SET {} WHERE tenant_id = $1 AND id = $2",
            updates.join(", ")
        );

        let mut query_builder = sqlx::query(&query).bind(tenant_id).bind(company_id);

        if let Some(ref name) = request.name {
            query_builder = query_builder.bind(name);
        }
        if let Some(ref ct) = request.company_type {
            query_builder = query_builder.bind(ct.as_str());
        }
        if let Some(ref status) = request.status {
            query_builder = query_builder.bind(status.as_str());
        }

        query_builder.execute(self.db.pool()).await?;

        self.get_company(tenant_id, company_id).await
    }

    /// Delete company
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_company(&self, tenant_id: Uuid, company_id: Uuid) -> AppResult<()> {
        // Check for related records
        let ticket_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND company_id = $2",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_one(self.db.pool())
        .await?;

        if ticket_count > 0 {
            return Err(AppError::BadRequest(
                "Cannot delete company with existing tickets".to_string(),
            ));
        }

        sqlx::query("DELETE FROM companies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(company_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    // ========================================================================
    // CONTACTS
    // ========================================================================

    /// Create a new contact
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_contact(
        &self,
        tenant_id: Uuid,
        request: &CreateContactRequest,
    ) -> AppResult<Contact> {
        // Verify company exists
        self.get_company(tenant_id, request.company_id).await?;

        let contact_id = Uuid::new_v4();
        let timezone = request
            .timezone
            .clone()
            .unwrap_or_else(|| "UTC".to_string());

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
        .execute(self.db.pool())
        .await?;

        // PMS-19: flip the contact's `is_portal_user` flag so the
        // upcoming portal-login flow (PMS-26) can treat it as a valid
        // identity. We deliberately do NOT mint a `portal_password_hash`
        // here because the password-set step belongs to the customer,
        // not the agent creating the contact - the portal-session work
        // will own the setup-link / email-confirmation handshake.
        if request.create_portal_access {
            sqlx::query(
                "UPDATE contacts SET is_portal_user = TRUE, updated_at = NOW() WHERE id = $1",
            )
            .bind(contact_id)
            .execute(self.db.pool())
            .await?;
        }

        self.get_contact(tenant_id, contact_id).await
    }

    /// Get contact by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_contact(&self, tenant_id: Uuid, contact_id: Uuid) -> AppResult<Contact> {
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
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Contact".to_string()))?;

        Ok(row.into())
    }

    /// List contacts with filters
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn list_contacts(
        &self,
        tenant_id: Uuid,
        filter: &ContactFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<Contact>, u64)> {
        let offset = pagination.offset() as i32;
        let limit = pagination.limit() as i32;

        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 4;

        if filter.q.is_some() {
            conditions.push(format!(
                "(first_name ILIKE ${} OR last_name ILIKE ${} OR email ILIKE ${})",
                param_idx, param_idx, param_idx
            ));
            param_idx += 1;
        }
        if filter.company_id.is_some() {
            conditions.push(format!("company_id = ${}", param_idx));
            param_idx += 1;
        }
        if filter.contact_type.is_some() {
            conditions.push(format!("contact_type = ${}", param_idx));
            param_idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${}", param_idx));
            // param_idx += 1;
        }

        let where_clause = conditions.join(" AND ");
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
            WHERE {}
            ORDER BY {}
            LIMIT $2 OFFSET $3
            "#,
            where_clause, order_by
        );

        let count_query = format!("SELECT COUNT(*) FROM contacts WHERE {}", where_clause);

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

        let rows = query_builder.fetch_all(self.db.pool()).await?;
        let total = count_builder.fetch_one(self.db.pool()).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// Get contacts for a company
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_company_contacts(
        &self,
        tenant_id: Uuid,
        company_id: Uuid,
    ) -> AppResult<Vec<Contact>> {
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
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Update contact
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_contact(
        &self,
        tenant_id: Uuid,
        contact_id: Uuid,
        request: &UpdateContactRequest,
    ) -> AppResult<Contact> {
        self.get_contact(tenant_id, contact_id).await?;

        // Simplified update - in production, use dynamic query building
        if let Some(ref first_name) = request.first_name {
            sqlx::query("UPDATE contacts SET first_name = $1, updated_at = NOW() WHERE tenant_id = $2 AND id = $3")
                .bind(first_name)
                .bind(tenant_id)
                .bind(contact_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(ref last_name) = request.last_name {
            sqlx::query("UPDATE contacts SET last_name = $1, updated_at = NOW() WHERE tenant_id = $2 AND id = $3")
                .bind(last_name)
                .bind(tenant_id)
                .bind(contact_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(ref email) = request.email {
            sqlx::query("UPDATE contacts SET email = $1, updated_at = NOW() WHERE tenant_id = $2 AND id = $3")
                .bind(email)
                .bind(tenant_id)
                .bind(contact_id)
                .execute(self.db.pool())
                .await?;
        }

        self.get_contact(tenant_id, contact_id).await
    }

    /// Delete contact
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_contact(&self, tenant_id: Uuid, contact_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM contacts WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(contact_id)
            .execute(self.db.pool())
            .await?;

        Ok(())
    }

    // ========================================================================
    // SITES
    // ========================================================================

    /// Create a new site
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn create_site(
        &self,
        tenant_id: Uuid,
        request: &CreateSiteRequest,
    ) -> AppResult<Site> {
        self.get_company(tenant_id, request.company_id).await?;

        let site_id = Uuid::new_v4();
        let address = request.address.clone().unwrap_or_default();
        let timezone = request
            .timezone
            .clone()
            .unwrap_or_else(|| "UTC".to_string());

        // If this is marked as primary, unmark other sites
        if request.is_primary {
            sqlx::query(
                "UPDATE sites SET is_primary = FALSE WHERE tenant_id = $1 AND company_id = $2",
            )
            .bind(tenant_id)
            .bind(request.company_id)
            .execute(self.db.pool())
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
        .execute(self.db.pool())
        .await?;

        self.get_site(tenant_id, site_id).await
    }

    /// Update a site. Audit F4: previously the route handler called
    /// `get_site` and silently returned the unchanged record.
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn update_site(
        &self,
        tenant_id: Uuid,
        site_id: Uuid,
        request: &UpdateSiteRequest,
    ) -> AppResult<Site> {
        // Verify site exists; also gives us the current company_id for
        // the is_primary unmark below.
        let current = self.get_site(tenant_id, site_id).await?;

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
            .execute(self.db.pool())
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

        q.execute(self.db.pool()).await?;

        self.get_site(tenant_id, site_id).await
    }

    /// Get site by ID
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_site(&self, tenant_id: Uuid, site_id: Uuid) -> AppResult<Site> {
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
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Site".to_string()))?;

        Ok(row.into())
    }

    /// Get sites for a company
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn get_company_sites(
        &self,
        tenant_id: Uuid,
        company_id: Uuid,
    ) -> AppResult<Vec<Site>> {
        let rows = sqlx::query_as::<_, SiteRow>(
            r#"
            SELECT id, tenant_id, company_id, name,
                   address_line1, address_line2, city, state, postal_code, country,
                   phone, is_primary, timezone, notes, latitude, longitude,
                   created_at, updated_at
            FROM sites
            WHERE tenant_id = $1 AND company_id = $2
            ORDER BY is_primary DESC, name
            "#,
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Delete site
    #[tracing::instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn delete_site(&self, tenant_id: Uuid, site_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM sites WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(site_id)
            .execute(self.db.pool())
            .await?;

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
            preferred_contact_method: PreferredContactMethod::Email,
            timezone: row.timezone,
            locale: row.locale,
            custom_fields: row.custom_fields,
            tags: row.tags,
            notes: row.notes,
            avatar_url: row.avatar_url,
            status: row.status.parse::<ContactStatus>().unwrap_or_default(),
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
