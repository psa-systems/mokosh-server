//! Assets HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use serde::Deserialize;

use super::models::*;
use super::service::{AssetsService, ImpactDirection};
use crate::db::Database;
use crate::modules::auth::{
    CallerContext, RequireAdmin, RequireAssets, RequireCallerContext, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct AssetsRouterState {
    pub service: Arc<AssetsService>,
}

pub fn assets_routes(service: AssetsService) -> Router {
    let state = AssetsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // PMS-73 asset types
        .route(
            "/asset-types",
            get(list_asset_types).post(create_asset_type),
        )
        .route(
            "/asset-types/{id}",
            put(update_asset_type).delete(delete_asset_type),
        )
        // PMS-74 assets
        .route("/assets", get(list_assets).post(create_asset))
        .route(
            "/assets/{id}",
            get(get_asset).put(update_asset).delete(delete_asset),
        )
        // PMS-75 relationships
        .route(
            "/assets/{id}/relationships",
            get(list_asset_relationships).post(create_asset_relationship),
        )
        .route(
            "/asset-relationships/{id}",
            axum::routing::delete(delete_asset_relationship),
        )
        // PMS-475: CI impact graph traversal. Walks asset_relationships
        // recursively to answer "if I retire this database, what
        // services break?" - the SPA's CI Map tab consumes it.
        .route("/assets/{id}/impact", get(get_asset_impact))
        // PMS-76 configuration items
        .route(
            "/assets/{id}/configuration-items",
            get(list_configuration_items).post(create_configuration_item),
        )
        .route(
            "/configuration-items/{id}",
            get(reveal_configuration_item).delete(delete_configuration_item),
        )
        // PMS-77 credential vault
        .route(
            "/assets/{id}/credentials",
            get(list_credentials).post(create_credential),
        )
        .route(
            "/credentials/{id}",
            get(reveal_credential).delete(delete_credential),
        )
        // PMS-78 audit log
        .route("/assets/{id}/audit-log", get(list_asset_audit_log))
        .with_state(state)
}

async fn list_asset_types(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AssetTypeResponse>>> {
    let (items, total) = s.service.list_asset_types(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_asset_type(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertAssetTypeRequest>,
) -> AppResult<Json<AssetTypeResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_asset_type(u.tenant(), &req, &ctx).await?,
    ))
}

async fn update_asset_type(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertAssetTypeRequest>,
) -> AppResult<Json<AssetTypeResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_asset_type(u.tenant(), id, &req).await?,
    ))
}

async fn delete_asset_type(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_asset_type(u.tenant(), id).await
}

async fn list_assets(
    State(s): State<AssetsRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Query(mut f): Query<AssetFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AssetResponse>>> {
    f.validate()?;
    // PMS-935: dual-plane sweep. Contact callers must hold
    // `assets:read` (DB-loaded per request; JWT `caps` is UI-only)
    // and get their listing scoped to their own Company so a spoofed
    // `company_id` query param cannot widen visibility. Staff callers
    // keep the pre-sweep RequireAssets module-gate + auth surface via
    // `assert_staff_authenticated` (staff role beyond auth is not
    // required for asset reads).
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => assert_staff_authenticated(auth)?,
        CallerContext::Contact(session) => {
            caller.require_capability(caps::ASSETS_READ, &db).await?;
            f.company_id = Some(session.company_id);
        }
    }
    let (items, total) = s.service.list_assets(tenant, &f, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_asset(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<CreateAssetRequest>,
) -> AppResult<Json<AssetResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_asset(u.tenant(), u.id, &req, &ctx).await?,
    ))
}

async fn get_asset(
    State(s): State<AssetsRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AssetResponse>> {
    // PMS-935: contact-plane callers 404 (not 403) on a foreign
    // Company's asset so a probe cannot confirm existence.
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => assert_staff_authenticated(auth)?,
        CallerContext::Contact(_) => {
            caller.require_capability(caps::ASSETS_READ, &db).await?;
        }
    }
    let asset = s.service.get_asset(tenant, id).await?;
    if let CallerContext::Contact(session) = &caller {
        if asset.company_id != session.company_id {
            return Err(AppError::NotFound("Asset".to_string()));
        }
    }
    Ok(Json(asset))
}

/// PMS-935: baseline "must be authenticated staff" check inlined
/// alongside the dual-plane read handlers. Reads used to sit behind
/// `RequireAssets` (module gate + auth) with no additional role
/// requirement; the sweep drops the module-gate piece so contact
/// callers with `assets:read` reach the endpoint regardless of the
/// tenant's staff-side module toggle. All child endpoints
/// (relationships, configuration items, credentials, impact graph,
/// audit log) stay behind `RequireAssets` and are therefore
/// implicitly staff-only: a contact bearer never populates
/// `AuthState`, so those extractors 401.
fn assert_staff_authenticated(auth: &crate::modules::auth::AuthState) -> AppResult<()> {
    auth.user.as_ref().ok_or(AppError::Unauthorized)?;
    Ok(())
}

async fn update_asset(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAssetRequest>,
) -> AppResult<Json<AssetResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_asset(u.tenant(), id, u.id, &req).await?,
    ))
}

async fn delete_asset(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_asset(u.tenant(), id, u.id).await
}

async fn list_asset_relationships(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AssetRelationshipResponse>>> {
    let (items, total) = s
        .service
        .list_asset_relationships(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_asset_relationship(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateAssetRelationshipRequest>,
) -> AppResult<Json<AssetRelationshipResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_asset_relationship(u.tenant(), id, &req, &ctx)
            .await?,
    ))
}

async fn delete_asset_relationship(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_asset_relationship(u.tenant(), id).await
}

/// PMS-475: query string for `GET /assets/{id}/impact`. Both fields
/// are optional; `direction` defaults to `both` and `depth` defaults
/// to the per-tenant `ci/impact_max_depth` setting (which the service
/// reads). The service clamps `depth` against that setting and the
/// hard server ceiling of 10.
#[derive(Debug, Deserialize)]
struct ImpactQuery {
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    depth: Option<u32>,
}

async fn get_asset_impact(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
    Query(q): Query<ImpactQuery>,
) -> AppResult<Json<AssetImpactResponse>> {
    let direction = match q.direction.as_deref().unwrap_or("both") {
        "upstream" => ImpactDirection::Upstream,
        "downstream" => ImpactDirection::Downstream,
        "both" => ImpactDirection::Both,
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown direction='{other}'; expected upstream | downstream | both",
            )));
        }
    };
    // 10 = the absolute server ceiling. The per-tenant setting clamps
    // further inside the service.
    let depth = q.depth.unwrap_or(10);
    let (effective_depth, rows) = s
        .service
        .compute_impact_graph(u.tenant(), id, direction, depth)
        .await?;
    let nodes: Vec<AssetImpactNode> = rows
        .into_iter()
        .map(|r| AssetImpactNode {
            asset_id: r.asset_id,
            name: r.name,
            parent_asset_id: r.parent_asset_id,
            child_asset_id: r.child_asset_id,
            relationship_type: r.relationship_type,
            direction: r.direction,
            depth: r.depth as u32,
        })
        .collect();
    Ok(Json(AssetImpactResponse {
        root_asset_id: id,
        depth: effective_depth,
        direction: match direction {
            ImpactDirection::Upstream => "upstream",
            ImpactDirection::Downstream => "downstream",
            ImpactDirection::Both => "both",
        }
        .to_string(),
        nodes,
    }))
}

async fn list_configuration_items(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ConfigurationItemSummary>>> {
    let (items, total) = s
        .service
        .list_configuration_items(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

/// Reveal a single configuration item's decrypted value (audited).
async fn reveal_configuration_item(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ConfigurationItemResponse>> {
    Ok(Json(
        s.service
            .reveal_configuration_item(u.tenant(), id, u.id)
            .await?,
    ))
}

async fn create_configuration_item(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertConfigurationItemRequest>,
) -> AppResult<Json<ConfigurationItemResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .upsert_configuration_item(u.tenant(), id, &req, &ctx)
            .await?,
    ))
}

async fn delete_configuration_item(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_configuration_item(u.tenant(), id).await
}

async fn list_credentials(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<CredentialSummary>>> {
    let (items, total) = s
        .service
        .list_credentials(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

/// Reveal a single credential's decrypted secrets (authz-gated + audited).
async fn reveal_credential(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
) -> AppResult<Json<CredentialResponse>> {
    Ok(Json(
        s.service.reveal_credential(u.tenant(), id, u.id).await?,
    ))
}

async fn create_credential(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateCredentialRequest>,
) -> AppResult<Json<CredentialResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_credential(u.tenant(), id, u.id, &req, &ctx)
            .await?,
    ))
}

async fn delete_credential(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_credential(u.tenant(), id, &ctx).await
}

async fn list_asset_audit_log(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AssetAuditLogResponse>>> {
    let (items, total) = s
        .service
        .list_asset_audit_log(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}
