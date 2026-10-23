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
