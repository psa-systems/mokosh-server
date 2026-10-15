//! HTTP surface for the asset catalog.
//!
//! Every route is gated on `Feature::AssetsCatalog`; the toggle off
//! returns 404 before any DB round trip so a tenant on an opt-out
//! deployment behaves the same as one on a server shipped before this
//! module. Write verbs sit behind `RequireAdmin`; the typeahead sits
//! behind `RequireAssets` so a non-admin viewing the Create modal can
//! still see matches.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    models::{AssetModelResponse, AssetModelsQuery, CreateAssetModelRequest},
    service::AssetCatalogService,
};
use crate::modules::auth::{RequireAdmin, RequireAssets, TenantScoped};
use crate::modules::features::FeatureSnapshot;
use crate::utils::error::{AppError, AppResult};
use crate::utils::json::Json;

#[derive(Clone)]
pub struct AssetCatalogRouterState {
    pub service: Arc<AssetCatalogService>,
    pub features: Option<FeatureSnapshot>,
}

pub fn asset_catalog_routes(service: AssetCatalogService, features: FeatureSnapshot) -> Router {
    let state = AssetCatalogRouterState {
        service: Arc::new(service),
        features: Some(features),
    };
    Router::new()
        .route(
            "/asset-models",
            get(list_asset_models).post(create_asset_model),
        )
        .route("/asset-models/{id}", get(get_asset_model))
        .with_state(state)
}

fn require_catalog(state: &AssetCatalogRouterState) -> AppResult<()> {
    let on = state
        .features
        .as_ref()
        .is_some_and(|s| s.is_enabled(crate::modules::features::registry::Feature::AssetsCatalog));
    if on {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "This endpoint is not enabled on this deployment".to_string(),
        ))
    }
}

async fn list_asset_models(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Query(query): Query<AssetModelsQuery>,
) -> AppResult<Json<Vec<AssetModelResponse>>> {
    require_catalog(&s)?;
    query.validate()?;
    let rows = s.service.search_models(u.tenant(), &query).await?;
    Ok(Json(rows))
}

async fn create_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _admin: RequireAdmin,
    Json(req): Json<CreateAssetModelRequest>,
) -> AppResult<(axum::http::StatusCode, Json<AssetModelResponse>)> {
    require_catalog(&s)?;
    req.validate()?;
    let row = s.service.create_model(u.tenant(), &req).await?;
    Ok((axum::http::StatusCode::CREATED, Json(row)))
}

async fn get_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AssetModelResponse>> {
    require_catalog(&s)?;
    let row = s.service.get_model(u.tenant(), id).await?;
    Ok(Json(row))
}
