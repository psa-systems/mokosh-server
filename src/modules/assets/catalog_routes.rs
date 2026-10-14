//! PMS-1488 asset catalog routes. Four mounts: `/asset-models`,
//! `/asset-templates`, `/assets/bulk-create`, and
//! `/asset-models/signature-detector`. All four are gated on the
//! `assets_catalog` feature toggle; off => 404 before any DB round
//! trip.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::catalog_models::*;
use super::catalog_service::{AssetCatalogService, AssetModelSource};
use crate::modules::auth::{tenant::TenantScoped, RequireAdmin, RequireAssets};
use crate::modules::features::{registry::Feature, FeatureSnapshot};
use crate::utils::error::{AppError, AppResult};
use crate::utils::json::Json;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct AssetCatalogRouterState {
    pub service: Arc<AssetCatalogService>,
    pub features: FeatureSnapshot,
}

pub fn asset_catalog_routes(service: AssetCatalogService, features: FeatureSnapshot) -> Router {
    let state = AssetCatalogRouterState {
        service: Arc::new(service),
        features,
    };
    Router::new()
        // Signature-detector FIRST so its "/signature-detector" path
        // segment does not match the "/{id}" variant below. Axum
        // picks the more specific match either way but ordering the
        // declaration this way reads more honestly.
        .route("/asset-models/signature-detector", get(signature_candidate))
        .route(
            "/asset-models",
            get(list_asset_models).post(create_asset_model),
        )
        .route(
            "/asset-models/{id}",
            get(get_asset_model)
                .put(update_asset_model)
                .delete(delete_asset_model),
        )
        .route(
            "/asset-templates",
            get(list_asset_templates).post(create_asset_template),
        )
        .route(
            "/asset-templates/{id}",
            get(get_asset_template)
                .put(update_asset_template)
                .delete(delete_asset_template),
        )
        .route("/assets/bulk-create", post(bulk_create_assets))
        .with_state(state)
}

fn require_catalog(state: &AssetCatalogRouterState) -> AppResult<()> {
    if state.features.is_enabled(Feature::AssetsCatalog) {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "This endpoint is not enabled on this deployment".to_string(),
        ))
    }
}

// -- asset-models --------------------------------------------------------

async fn list_asset_models(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Query(filter): Query<AssetModelListFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AssetModelResponse>>> {
    require_catalog(&s)?;
    filter.validate()?;
    pagination.reject_unsupported_sort()?;
    let (items, total) = s
        .service
        .list_models(u.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AssetModelResponse>> {
    require_catalog(&s)?;
    Ok(Json(s.service.get_model(u.tenant(), id).await?))
}

async fn create_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Json(req): Json<CreateAssetModelRequest>,
) -> AppResult<Json<AssetModelResponse>> {
    require_catalog(&s)?;
    req.validate()?;
    Ok(Json(
        s.service
            .create_model(u.tenant(), AssetModelSource::TenantAuthored, &req)
            .await?,
    ))
}

async fn update_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAssetModelRequest>,
) -> AppResult<Json<AssetModelResponse>> {
    require_catalog(&s)?;
    req.validate()?;
    Ok(Json(s.service.update_model(u.tenant(), id, &req).await?))
}

async fn delete_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    require_catalog(&s)?;
    s.service.delete_model(u.tenant(), id).await
}

// -- asset-templates -----------------------------------------------------

async fn list_asset_templates(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AssetTemplateResponse>>> {
    require_catalog(&s)?;
    pagination.reject_unsupported_sort()?;
    let (items, total) = s.service.list_templates(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn get_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AssetTemplateResponse>> {
    require_catalog(&s)?;
    Ok(Json(s.service.get_template(u.tenant(), id).await?))
}

async fn create_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Json(req): Json<CreateAssetTemplateRequest>,
) -> AppResult<Json<AssetTemplateResponse>> {
    require_catalog(&s)?;
    req.validate()?;
    Ok(Json(
        s.service.create_template(u.tenant(), u.id, &req).await?,
    ))
}

async fn update_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAssetTemplateRequest>,
) -> AppResult<Json<AssetTemplateResponse>> {
    require_catalog(&s)?;
    req.validate()?;
    Ok(Json(s.service.update_template(u.tenant(), id, &req).await?))
}

async fn delete_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    require_catalog(&s)?;
    s.service.delete_template(u.tenant(), id).await
}

// -- bulk-create ----------------------------------------------------------

async fn bulk_create_assets(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Json(req): Json<BulkCreateAssetsRequest>,
) -> AppResult<Json<BulkCreateAssetsResponse>> {
    require_catalog(&s)?;
    req.validate()?;
    for (i, sr) in req.serials.iter().enumerate() {
        if let Err(e) = sr.validate() {
            return Err(AppError::validation_field(
                format!("serials[{i}]"),
                format!("row rejected at validation: {e}"),
            ));
        }
    }
    Ok(Json(s.service.bulk_create(u.tenant(), u.id, &req).await?))
}

// -- signature-detector -------------------------------------------------

async fn signature_candidate(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
) -> AppResult<Json<Option<SignatureCandidateResponse>>> {
    require_catalog(&s)?;
    Ok(Json(s.service.top_signature_candidate(u.tenant()).await?))
}
