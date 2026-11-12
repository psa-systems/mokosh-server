//! MAPPS-1099 Phase 2c: HTTP surface for the invoice-issuer mapping
//! tables.
//!
//! Four admin-only routes behind `Feature::DelegatedInvoiceIssuer`: a
//! `PUT` on `/api/v1/invoice-issuer-mappings/companies/{provider}/{company_id}`
//! and on `/api/v1/invoice-issuer-mappings/products/{provider}/{product_id}`,
//! and a `GET` listing each. Off: every route answers 404 (not 403) so a
//! probe of a deployment that has not opted into the flag cannot tell the
//! mappings table exists at all. On: the `RequireAdmin` +
//! `RequireFinance` pair of today's billing surface applies; the service
//! layer PR 2b-rest shipped carries the write itself.
//!
//! MAPPS-1155 added the bill half, four more routes on the same prefix:
//! vendors (which vendor a bill is raised against over there) and
//! expense accounts (which ledger account a category's lines post to),
//! called by the same Mappings page since MAPPS-1156.
//!
//! PMS-1541 added the people half, two more: which contact a member of
//! the tenant is in the provider, which a reimbursement names. Xero
//! refuses a bank transaction without one, where QuickBooks sends it as
//! an optional `EntityRef`; the Mappings page has said which is which
//! since MAPPS-1168.
//! Those four read `Feature::DelegatedBills`, not
//! `Feature::DelegatedInvoiceIssuer`, because they serve a different
//! switch: a deployment can delegate bills without delegating invoices,
//! and a mapping surface that 404s on the flag its own dispatcher does
//! not read would be unreachable exactly when it is needed.
//!
//! There is no DELETE. This header claimed one from the start and none
//! was ever mounted; a mapping is overwritten rather than removed, and
//! unmapping a company is a bigger decision than clearing a text field
//! (MAPPS-1146).
//!
//! The dispatch that READS these mappings in `BillingService::create_invoice`
//! is Phase 2d; this PR gives operations the surface to populate the
//! tables so a Phase 2d flip-the-switch run has something to resolve.
//!
//! MAPPS-1146 retired the parity exemption these routes carried rather
//! than re-dating it: Settings > Integrations > {Xero,QuickBooks} >
//! Mappings calls all four. The record pointed the next reader at
//! MAPPS-1172 for the surface that would call them, and no such issue
//! exists; a reference to nothing is worse than no reference, which is
//! why the replacement is a caller and not a newer date.

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
    CompanyMapping, ExpenseAccountMapping, InvoiceIssuerMappingService, ProductMapping,
    UserMapping, VendorMapping,
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
        .route(
            "/invoice-issuer-mappings/vendors",
            get(list_vendor_mappings),
        )
        .route(
            "/invoice-issuer-mappings/vendors/{provider}/{vendor_id}",
            put(upsert_vendor_mapping),
        )
        .route(
            "/invoice-issuer-mappings/expense-accounts",
            get(list_expense_account_mappings),
        )
        .route(
            "/invoice-issuer-mappings/expense-accounts/{provider}/{category_id}",
            put(upsert_expense_account_mapping),
        )
        .route("/invoice-issuer-mappings/people", get(list_user_mappings))
        .route(
            "/invoice-issuer-mappings/people/{provider}/{user_id}",
            put(upsert_user_mapping),
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

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertVendorMappingRequest {
    #[validate(length(min = 1, max = 100))]
    pub external_vendor_id: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertExpenseAccountMappingRequest {
    #[validate(length(min = 1, max = 100))]
    pub external_account_id: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertUserMappingRequest {
    #[validate(length(min = 1, max = 100))]
    pub external_contact_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListUserMappingsResponse {
    pub mappings: Vec<UserMapping>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListVendorMappingsResponse {
    pub mappings: Vec<VendorMapping>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListExpenseAccountMappingsResponse {
    pub mappings: Vec<ExpenseAccountMapping>,
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

/// Flag check for the bill half (MAPPS-1155): 404 when
/// `Feature::DelegatedBills` is off, same posture and same reason as
/// [`require_delegated_issuer`], a different switch.
fn require_delegated_bills(state: &InvoiceIssuerMappingRouterState) -> AppResult<()> {
    if state
        .features
        .is_enabled(crate::modules::features::Feature::DelegatedBills)
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

async fn list_vendor_mappings(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
) -> AppResult<Json<ListVendorMappingsResponse>> {
    require_delegated_bills(&state)?;
    let mappings = state.service.list_vendor_mappings(user.tenant()).await?;
    Ok(Json(ListVendorMappingsResponse { mappings }))
}

async fn upsert_vendor_mapping(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
    Path((provider_raw, vendor_id)): Path<(String, Uuid)>,
    Json(request): Json<UpsertVendorMappingRequest>,
) -> AppResult<Json<VendorMapping>> {
    require_delegated_bills(&state)?;
    request.validate()?;
    let provider = parse_provider(&provider_raw)?;
    let row = state
        .service
        .upsert_vendor_mapping(
            user.tenant(),
            provider,
            vendor_id,
            &request.external_vendor_id,
        )
        .await?;
    Ok(Json(row))
}

async fn list_expense_account_mappings(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
) -> AppResult<Json<ListExpenseAccountMappingsResponse>> {
    require_delegated_bills(&state)?;
    let mappings = state
        .service
        .list_expense_account_mappings(user.tenant())
        .await?;
    Ok(Json(ListExpenseAccountMappingsResponse { mappings }))
}

async fn upsert_expense_account_mapping(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
    Path((provider_raw, category_id)): Path<(String, Uuid)>,
    Json(request): Json<UpsertExpenseAccountMappingRequest>,
) -> AppResult<Json<ExpenseAccountMapping>> {
    require_delegated_bills(&state)?;
    request.validate()?;
    let provider = parse_provider(&provider_raw)?;
    let row = state
        .service
        .upsert_expense_account_mapping(
            user.tenant(),
            provider,
            category_id,
            &request.external_account_id,
        )
        .await?;
    Ok(Json(row))
}

async fn list_user_mappings(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
) -> AppResult<Json<ListUserMappingsResponse>> {
    require_delegated_bills(&state)?;
    let mappings = state.service.list_user_mappings(user.tenant()).await?;
    Ok(Json(ListUserMappingsResponse { mappings }))
}

async fn upsert_user_mapping(
    State(state): State<InvoiceIssuerMappingRouterState>,
    RequireBilling { user, .. }: RequireBilling,
    _finance: RequireFinance,
    _admin: RequireAdmin,
    Path((provider_raw, user_id)): Path<(String, Uuid)>,
    Json(request): Json<UpsertUserMappingRequest>,
) -> AppResult<Json<UserMapping>> {
    require_delegated_bills(&state)?;
    request.validate()?;
    let provider = parse_provider(&provider_raw)?;
    let row = state
        .service
        .upsert_user_mapping(
            user.tenant(),
            provider,
            user_id,
            &request.external_contact_id,
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
