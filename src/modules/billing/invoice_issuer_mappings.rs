//! MAPPS-1099 Phase 2b-rest: Mokosh -> external invoice-issuer mapping
//! service.
//!
//! A delegated invoice carries three ids the local path never cared
//! about: the external customer id (Xero `ContactID` / QuickBooks
//! `CustomerRef.value`) the invoice is billed to, the external item id
//! each line references, and the external organisation / realm the
//! whole call is scoped to. The customer and item mappings live in
//! their own tables (`invoice_issuer_company_mappings`,
//! `invoice_issuer_product_mappings`, migration 282); the external
//! organisation / realm sits on `integrations.external_organisation_id`.
//!
//! This module is the read-side surface over all three. Phase 2c (the
//! follow-up) adds the admin SPA that writes these rows and the
//! dispatch that reads them from `create_invoice`. Nothing calls the
//! methods here yet; shipping the service alongside the schema keeps
//! the next step a small, reviewable PR instead of one that moves
//! schema and callers at the same time.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::modules::billing::invoice_issuer::InvoiceProviderKind;
use crate::utils::error::{AppError, AppResult};

/// One row of `invoice_issuer_company_mappings`: a Mokosh company
/// maps to the external customer the provider knows it as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct CompanyMapping {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub company_id: Uuid,
    pub external_customer_id: String,
}

/// One row of `invoice_issuer_vendor_mappings`: a Mokosh vendor maps to
/// the vendor a bill is raised against in the provider (MAPPS-1155).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct VendorMapping {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub vendor_id: Uuid,
    pub external_vendor_id: String,
}

/// One row of `invoice_issuer_user_mappings`: a member of the tenant maps
/// to the contact the provider knows them as (PMS-1541).
///
/// A reimbursement names the person who was paid back, and Xero refuses a
/// bank transaction with no `Contact` at all.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserMapping {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub user_id: Uuid,
    pub external_contact_id: String,
}

/// One row of `invoice_issuer_expense_account_mappings`: a Mokosh
/// expense category maps to the ledger account a delegated bill line
/// posts to (MAPPS-1155).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ExpenseAccountMapping {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub category_id: Uuid,
    pub external_account_id: String,
}

/// One row of `invoice_issuer_product_mappings`: a Mokosh product
/// maps to the external item each line of a delegated invoice has to
/// name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct ProductMapping {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub product_id: Uuid,
    pub external_item_id: String,
}

/// Read-side service over the three mapping surfaces an external
/// delegated issue needs. Writes land in Phase 2c with the admin SPA
/// surfaces that build the mappings.
#[derive(Clone)]
pub struct InvoiceIssuerMappingService {
    db: Database,
}

impl InvoiceIssuerMappingService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Resolve the external customer id for one Mokosh company. Returns
    /// `None` when no mapping has been set for this `(tenant, provider,
    /// company)` triple; the dispatcher turns that into a well-known
    /// refusal ("company X is not mapped to a <provider> customer")
    /// rather than silently sending the row without a `ContactID`.
    pub async fn get_customer_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        company_id: Uuid,
    ) -> AppResult<Option<CompanyMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<CompanyMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, company_id, external_customer_id
               FROM invoice_issuer_company_mappings
               WHERE tenant_id = $1 AND provider = $2 AND company_id = $3"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(company_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(row)
    }

    /// Batched sibling of [`Self::get_customer_mapping`] for the lines
    /// of one invoice. Returns a map keyed by `product_id` so the
    /// caller resolves every line's `external_item_id` with one round
    /// trip; an unmapped product id is absent from the map and the
    /// dispatcher refuses the issue at a named line.
    pub async fn get_product_mappings(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        product_ids: &[Uuid],
    ) -> AppResult<std::collections::HashMap<Uuid, ProductMapping>> {
        if product_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<ProductMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, product_id, external_item_id
               FROM invoice_issuer_product_mappings
               WHERE tenant_id = $1 AND provider = $2 AND product_id = ANY($3)"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(product_ids)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows.into_iter().map(|r| (r.product_id, r)).collect())
    }

    /// Resolve the external vendor id for one Mokosh vendor (MAPPS-1155).
    ///
    /// The bill half of [`Self::get_customer_mapping`]. A bill names a
    /// vendor over there the way an invoice names a customer, and the
    /// two cannot share a table: the company mapping's `company_id` is
    /// a foreign key into `companies` and a vendor is a row in
    /// `vendors`.
    pub async fn get_vendor_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        vendor_id: Uuid,
    ) -> AppResult<Option<VendorMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<VendorMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, vendor_id, external_vendor_id
               FROM invoice_issuer_vendor_mappings
               WHERE tenant_id = $1 AND provider = $2 AND vendor_id = $3"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(vendor_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Every vendor mapping this tenant holds for one provider, for the
    /// admin surface that lists vendors beside what they are over there.
    pub async fn list_vendor_mappings(&self, tenant_id: TenantId) -> AppResult<Vec<VendorMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<VendorMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, vendor_id, external_vendor_id
               FROM invoice_issuer_vendor_mappings
               WHERE tenant_id = $1
               ORDER BY created_at"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Set (or replace) the vendor mapping for a `(tenant, provider,
    /// vendor)` triple.
    pub async fn upsert_vendor_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        vendor_id: Uuid,
        external_vendor_id: &str,
    ) -> AppResult<VendorMapping> {
        if external_vendor_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "external_vendor_id cannot be blank".to_string(),
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: VendorMapping = sqlx::query_as(
            r#"INSERT INTO invoice_issuer_vendor_mappings
                 (tenant_id, provider, vendor_id, external_vendor_id)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, provider, vendor_id) DO UPDATE
                 SET external_vendor_id = EXCLUDED.external_vendor_id,
                     updated_at = NOW()
               RETURNING id, tenant_id, provider, vendor_id, external_vendor_id"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(vendor_id)
        .bind(external_vendor_id.trim())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Resolve the ledger account for each expense category one bill
    /// touches (MAPPS-1155).
    ///
    /// Batched for the same reason [`Self::get_product_mappings`] is:
    /// one round trip for the whole bill, and a category absent from the
    /// map is the refusal the dispatcher names a line with.
    pub async fn get_expense_account_mappings(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        category_ids: &[Uuid],
    ) -> AppResult<std::collections::HashMap<Uuid, ExpenseAccountMapping>> {
        if category_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<ExpenseAccountMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, category_id, external_account_id
               FROM invoice_issuer_expense_account_mappings
               WHERE tenant_id = $1 AND provider = $2 AND category_id = ANY($3)"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(category_ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(|r| (r.category_id, r)).collect())
    }

    /// Every expense-account mapping this tenant holds, both providers,
    /// for the admin surface that lists categories beside the account
    /// they post to.
    pub async fn list_expense_account_mappings(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<Vec<ExpenseAccountMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<ExpenseAccountMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, category_id, external_account_id
               FROM invoice_issuer_expense_account_mappings
               WHERE tenant_id = $1
               ORDER BY provider, category_id"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Set (or replace) the account mapping for a `(tenant, provider,
    /// category)` triple.
    pub async fn upsert_expense_account_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        category_id: Uuid,
        external_account_id: &str,
    ) -> AppResult<ExpenseAccountMapping> {
        if external_account_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "external_account_id cannot be blank".to_string(),
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: ExpenseAccountMapping = sqlx::query_as(
            r#"INSERT INTO invoice_issuer_expense_account_mappings
                 (tenant_id, provider, category_id, external_account_id)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, provider, category_id) DO UPDATE
                 SET external_account_id = EXCLUDED.external_account_id,
                     updated_at = NOW()
               RETURNING id, tenant_id, provider, category_id, external_account_id"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(category_id)
        .bind(external_account_id.trim())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// The provider account a reimbursement is paid from (PMS-1541).
    ///
    /// Read from the `integrations` row rather than a mapping table,
    /// because one value per tenant per provider is what it is; it lives
    /// here rather than on `IntegrationResponse` so the dispatcher reads
    /// every provider-side id through one seam, and so a widely used
    /// response type does not grow a field only this path wants.
    pub async fn get_payment_account(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
    ) -> AppResult<Option<String>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let value: Option<Option<String>> = sqlx::query_scalar(
            "SELECT external_payment_account_id FROM integrations \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        // Two layers of absence collapse to one on purpose: no integration
        // row and a row with no account set are the same answer to "can
        // this tenant be reimbursed through the provider", and the
        // dispatcher's refusal names the same route either way.
        Ok(value.flatten().filter(|v| !v.trim().is_empty()))
    }

    /// Resolve the provider contact for one member of the tenant
    /// (PMS-1541).
    ///
    /// One per reimbursement rather than a batch: a claim names one
    /// submitter, where a bill names one vendor and many categories.
    pub async fn get_user_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        user_id: Uuid,
    ) -> AppResult<Option<UserMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<UserMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, user_id, external_contact_id
               FROM invoice_issuer_user_mappings
               WHERE tenant_id = $1 AND provider = $2 AND user_id = $3"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Every people mapping this tenant holds, for the admin surface that
    /// lists members beside who they are over there.
    pub async fn list_user_mappings(&self, tenant_id: TenantId) -> AppResult<Vec<UserMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<UserMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, user_id, external_contact_id
               FROM invoice_issuer_user_mappings
               WHERE tenant_id = $1
               ORDER BY provider, user_id"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Set (or replace) the people mapping for a `(tenant, provider,
    /// user)` triple.
    pub async fn upsert_user_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        user_id: Uuid,
        external_contact_id: &str,
    ) -> AppResult<UserMapping> {
        if external_contact_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "external_contact_id cannot be blank".to_string(),
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: UserMapping = sqlx::query_as(
            r#"INSERT INTO invoice_issuer_user_mappings
                 (tenant_id, provider, user_id, external_contact_id)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, provider, user_id) DO UPDATE
                 SET external_contact_id = EXCLUDED.external_contact_id,
                     updated_at = NOW()
               RETURNING id, tenant_id, provider, user_id, external_contact_id"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(user_id)
        .bind(external_contact_id.trim())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Set (or replace) the customer mapping for a `(tenant, provider,
    /// company)` triple. Phase 2c's admin SPA calls this through a
    /// dedicated handler; the service method ships now so Phase 2c
    /// does not have to touch two files at once.
    pub async fn upsert_customer_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        company_id: Uuid,
        external_customer_id: &str,
    ) -> AppResult<CompanyMapping> {
        if external_customer_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "external_customer_id cannot be blank".to_string(),
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: CompanyMapping = sqlx::query_as(
            r#"INSERT INTO invoice_issuer_company_mappings
                 (tenant_id, provider, company_id, external_customer_id)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, provider, company_id) DO UPDATE
                 SET external_customer_id = EXCLUDED.external_customer_id,
                     updated_at = NOW()
               RETURNING id, tenant_id, provider, company_id, external_customer_id"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(company_id)
        .bind(external_customer_id.trim())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Every company mapping this tenant has, both providers. Used by
    /// the admin SPA's listing surface.
    pub async fn list_company_mappings(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<Vec<CompanyMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<CompanyMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, company_id, external_customer_id
               FROM invoice_issuer_company_mappings
               WHERE tenant_id = $1
               ORDER BY provider, company_id"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows)
    }

    /// Every product mapping this tenant has, both providers. Same
    /// shape as [`Self::list_company_mappings`].
    pub async fn list_product_mappings(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<Vec<ProductMapping>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<ProductMapping> = sqlx::query_as(
            r#"SELECT id, tenant_id, provider, product_id, external_item_id
               FROM invoice_issuer_product_mappings
               WHERE tenant_id = $1
               ORDER BY provider, product_id"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows)
    }

    /// Set (or replace) the product mapping for one `(tenant, provider,
    /// product)` triple. Same shape as [`Self::upsert_customer_mapping`].
    pub async fn upsert_product_mapping(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        product_id: Uuid,
        external_item_id: &str,
    ) -> AppResult<ProductMapping> {
        if external_item_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "external_item_id cannot be blank".to_string(),
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: ProductMapping = sqlx::query_as(
            r#"INSERT INTO invoice_issuer_product_mappings
                 (tenant_id, provider, product_id, external_item_id)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant_id, provider, product_id) DO UPDATE
                 SET external_item_id = EXCLUDED.external_item_id,
                     updated_at = NOW()
               RETURNING id, tenant_id, provider, product_id, external_item_id"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(product_id)
        .bind(external_item_id.trim())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }
}
