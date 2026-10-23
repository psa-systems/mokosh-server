//! MAPPS-1099 Phase 2c: HTTP surface for the invoice-issuer mapping
//! tables.
//!
//! Four admin-only routes behind `Feature::DelegatedInvoiceIssuer`:
//! `PUT`/`DELETE` on `/api/v1/invoice-issuer-mappings/companies/{provider}/{company_id}`
//! and `/api/v1/invoice-issuer-mappings/products/{provider}/{product_id}`,
//! plus two `GET`s for the admin listing surface. Off: every route
//! answers 404 (not 403) so a probe of a deployment that has not opted
//! into the flag cannot tell the mappings table exists at all. On: the
//! `RequireAdmin` + `RequireFinance` pair of today's billing surface
//! applies; the service layer PR 2b-rest shipped carries the write
//! itself.
//!
//! The dispatch that READS these mappings in `BillingService::create_invoice`
//! is Phase 2d; this PR gives operations the surface to populate the
//! tables so a Phase 2d flip-the-switch run has something to resolve.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{get, put},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::modules::auth::{RequireAdmin, RequireBilling, RequireFinance, TenantScoped};
use crate::modules::billing::invoice_issuer::InvoiceProviderKind;
use crate::modules::billing::invoice_issuer_mappings::{
    CompanyMapping, InvoiceIssuerMappingService, ProductMapping,
};
use crate::modules::features::FeatureSnapshot;
use crate::utils::error::{AppError, AppResult};
use crate::utils::json::Json;

#[derive(Clone)]
pub struct InvoiceIssuerMappingRouterState {
    pub service: Arc<InvoiceIssuerMappingService>,
    pub features: FeatureSnapshot,
}

/// Build the invoice-issuer mapping router.
pub fn invoice_issuer_mapping_routes(state: InvoiceIssuerMappingRouterState) -> Router {
    Router::new()
        .route(
            "/invoice-issuer-mappings/companies",
            get(list_company_mappings),
        )
        .route(
            "/invoice-issuer-mappings/companies/{provider}/{company_id}",
            put(upsert_company_mapping),
        )
        .route(
            "/invoice-issuer-mappings/products",
            get(list_product_mappings),
        )
        .route(
            "/invoice-issuer-mappings/products/{provider}/{product_id}",
            put(upsert_product_mapping),
        )
        .with_state(state)
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertCompanyMappingRequest {
    #[validate(length(min = 1, max = 100))]
    pub external_customer_id: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertProductMappingRequest {
    #[validate(length(min = 1, max = 100))]
    pub external_item_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListCompanyMappingsResponse {
    pub mappings: Vec<CompanyMapping>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListProductMappingsResponse {
    pub mappings: Vec<ProductMapping>,
}

/// Flag check: 404 when `Feature::DelegatedInvoiceIssuer` is off. 404
/// (not 403) so a probe cannot tell the mapping surface exists at all;
/// matches the `require_search_v2` posture `assets/routes.rs` uses.
fn require_delegated_issuer(state: &InvoiceIssuerMappingRouterState) -> AppResult<()> {
    if state
        .features
        .is_enabled(crate::modules::features::Feature::DelegatedInvoiceIssuer)
    {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "This endpoint is not enabled on this deployment".to_string(),
        ))
    }
}

fn parse_provider(raw: &str) -> AppResult<InvoiceProviderKind> {
    InvoiceProviderKind::parse(raw).ok_or_else(|| {
        AppError::BadRequest(format!(
            "'{raw}' is not a delegated invoice-issuer provider; expected xero or quickbooks"
        ))
    })
}

async fn list_company_mappings(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
) -> AppResult<Json<ListCompanyMappingsResponse>> {
    require_delegated_issuer(&state)?;
    let mappings = state.service.list_company_mappings(user.tenant()).await?;
    Ok(Json(ListCompanyMappingsResponse { mappings }))
}

async fn upsert_company_mapping(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
    Path((provider_raw, company_id)): Path<(String, Uuid)>,
    Json(request): Json<UpsertCompanyMappingRequest>,
) -> AppResult<Json<CompanyMapping>> {
    require_delegated_issuer(&state)?;
    request.validate()?;
    let provider = parse_provider(&provider_raw)?;
    let row = state
        .service
        .upsert_customer_mapping(
            user.tenant(),
            provider,
            company_id,
            &request.external_customer_id,
        )
        .await?;
    Ok(Json(row))
}

async fn list_product_mappings(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
) -> AppResult<Json<ListProductMappingsResponse>> {
    require_delegated_issuer(&state)?;
    let mappings = state.service.list_product_mappings(user.tenant()).await?;
    Ok(Json(ListProductMappingsResponse { mappings }))
}

async fn upsert_product_mapping(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
    Path((provider_raw, product_id)): Path<(String, Uuid)>,
    Json(request): Json<UpsertProductMappingRequest>,
) -> AppResult<Json<ProductMapping>> {
    require_delegated_issuer(&state)?;
    request.validate()?;
    let provider = parse_provider(&provider_raw)?;
    let row = state
        .service
        .upsert_product_mapping(
            user.tenant(),
            provider,
            product_id,
            &request.external_item_id,
        )
        .await?;
    Ok(Json(row))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parsing_rejects_names_outside_the_delegated_set() {
        assert_eq!(parse_provider("xero").unwrap(), InvoiceProviderKind::Xero);
        assert_eq!(
            parse_provider("quickbooks").unwrap(),
            InvoiceProviderKind::Quickbooks
        );
        let err = parse_provider("stripe").unwrap_err();
        assert!(
            matches!(err, AppError::BadRequest(_)),
            "stripe is a payment provider, not a delegated invoice issuer: {err:?}"
        );
    }
}
