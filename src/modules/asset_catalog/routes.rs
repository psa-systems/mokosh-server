//! HTTP surface for the asset catalog.
//!
//! Every route is gated on `Feature::AssetsCatalog`; the toggle off
//! returns 404 before any DB round trip so a tenant on an opt-out
//! deployment behaves the same as one on a server shipped before this
//! module. Write verbs sit behind `RequireAdmin`; the typeahead sits
//! behind `RequireAssets` so a non-admin viewing the Create modal can
//! still see matches.
//!
//! parity record 2026-10-15: `/asset-templates` and
//! `/asset-templates/{id}` have no SPA caller yet. The admin page the
//! design doc commits to (`/settings/asset-catalog` on the SPA; see
//! docs/mokosh-assets/04-templates-and-bulk-order.md) is MAPPS-xxxx and
//! has not shipped. The bulk-create flow consumes templates
//! server-side via `POST /assets/bulk-create` with `template_id` set
//! (which IS exercised from the SPA's `AssetBulkCreateModal`), so the
//! template CRUD lands here now so the admin page can build against a
//! stable surface. The note comes off with the first SPA call.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    models::{
        AssetModelResponse, AssetModelsQuery, AssetTemplateResponse, CreateAssetModelRequest,
        CreateAssetTemplateRequest, SignatureDetectorResponse, UpdateAssetModelRequest,
        UpdateAssetTemplateRequest,
    },
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
        // PMS-1492 MR3: signature-detector read. Must be registered
        // BEFORE the `/asset-models/{id}` route or Axum's path matcher
        // would treat "signature-detector" as a UUID candidate and
        // return 400.
        .route("/asset-models/signature-detector", get(signature_detector))
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

async fn signature_detector(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
) -> AppResult<Json<SignatureDetectorResponse>> {
    require_catalog(&s)?;
    let resp = s.service.signature_detector(u.tenant()).await?;
    Ok(Json(resp))
}

async fn update_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAssetModelRequest>,
) -> AppResult<Json<AssetModelResponse>> {
    require_catalog(&s)?;
    req.validate()?;
    let row = s.service.update_model(u.tenant(), id, &req).await?;
    Ok(Json(row))
}

async fn delete_asset_model(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    require_catalog(&s)?;
    s.service.delete_model(u.tenant(), id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn list_asset_templates(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
) -> AppResult<Json<Vec<AssetTemplateResponse>>> {
    require_catalog(&s)?;
    let rows = s.service.list_templates(u.tenant()).await?;
    Ok(Json(rows))
}

async fn get_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AssetTemplateResponse>> {
    require_catalog(&s)?;
    let row = s.service.get_template(u.tenant(), id).await?;
    Ok(Json(row))
}

async fn create_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _admin: RequireAdmin,
    Json(req): Json<CreateAssetTemplateRequest>,
) -> AppResult<(axum::http::StatusCode, Json<AssetTemplateResponse>)> {
    require_catalog(&s)?;
    req.validate()?;
    let row = s.service.create_template(u.tenant(), u.id, &req).await?;
    Ok((axum::http::StatusCode::CREATED, Json(row)))
}

async fn update_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAssetTemplateRequest>,
) -> AppResult<Json<AssetTemplateResponse>> {
    require_catalog(&s)?;
    req.validate()?;
    let row = s.service.update_template(u.tenant(), id, &req).await?;
    Ok(Json(row))
}

async fn delete_asset_template(
    State(s): State<AssetCatalogRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _admin: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    require_catalog(&s)?;
    s.service.delete_template(u.tenant(), id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
