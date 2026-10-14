//! Assets HTTP routes.
//!
//! parity record 2026-10-14: `/assets/search/facets` has no SPA caller
//! yet. The pill-based filter bar (MAPPS-xxxx, phase 1 SPA) renders the
//! facet counts in a sidebar beside the pill set; both the search POST
//! and the facets POST ship together on that MR. The note comes off
//! with the first client call. Both routes are gated on the
//! `assets_search_v2` feature toggle so a deployment with the switch
//! off answers 404 regardless of whether the SPA renders them yet.

use std::sync::Arc;

use crate::utils::json::Json;
use axum::{
    extract::{Path, Query, State},
    routing::{get, put},
    Router,
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
use crate::modules::tickets::{TicketResponse, TicketService};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct AssetsRouterState {
    pub service: Arc<AssetsService>,
    /// PMS-936: the `POST /assets/{id}/report-issue` endpoint creates a
    /// ticket linked to the asset, so the router needs a
    /// `TicketService` clone alongside the assets one. Optional to
    /// keep call sites that only exercise the assets surface (unit
    /// tests, seed) trivially constructible.
    pub ticket_service: Option<Arc<TicketService>>,
    /// PMS-1486: the feature-toggle snapshot gates the new search
    /// routes. The handler reads `assets_search_v2`; off => 404
    /// before any DB round trip. Optional so test-rig call sites that
    /// do not exercise the search can leave it `None` (snapshot
    /// defaults to all-features-off, which produces the same 404).
    pub features: Option<crate::modules::features::FeatureSnapshot>,
}

pub fn assets_routes(
    service: AssetsService,
    ticket_service: TicketService,
    features: crate::modules::features::FeatureSnapshot,
) -> Router {
    let state = AssetsRouterState {
        service: Arc::new(service),
        ticket_service: Some(Arc::new(ticket_service)),
        features: Some(features),
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
        // PMS-1486: structured-filter search + the sidebar facet counts.
        // Both gated on the `assets_search_v2` feature toggle; off => 404.
        // The POST body carries the filter shape rather than the query
        // string so the SPA's pill set can grow without a URL-length cap.
        .route(
            "/assets/search",
            axum::routing::post(search_assets_structured),
        )
        .route(
            "/assets/search/facets",
            axum::routing::post(asset_facets_structured),
        )
        .route(
            "/assets/{id}",
            get(get_asset)
                .put(update_asset)
                .patch(patch_asset)
                .delete(delete_asset),
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
        // PMS-936: contact-plane (or staff) opens a ticket linked to a
        // specific asset. Gated on `assets:report_issue` for contacts;
        // creates a `source = portal` ticket with `asset_id` set on
        // the row so the report is discoverable from the asset detail.
        .route(
            "/assets/{id}/report-issue",
            axum::routing::post(report_asset_issue),
        )
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
    pagination.reject_unsupported_sort()?;
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
) -> AppResult<axum::response::Response> {
    pagination.reject_unsupported_sort()?;
    use axum::response::IntoResponse;
    f.validate()?;
    // PMS-935: dual-plane sweep. Contact callers must hold
    // `assets:read` (DB-loaded per request; JWT `caps` is UI-only)
    // and get their listing scoped to their own Company so a spoofed
    // `company_id` query param cannot widen visibility. Staff callers
    // keep the pre-sweep RequireAssets module-gate + auth surface via
    // `assert_staff_authenticated` (staff role beyond auth is not
    // required for asset reads). PMS-1061: the contact arm answers with
    // `ContactAssetResponse`, the customer's projection, never the staff
    // type.
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => assert_staff_authenticated(auth)?,
        CallerContext::Contact(session) => {
            caller.require_capability(caps::ASSETS_READ, &db).await?;
            f.company_id = Some(session.company_id);
        }
    }
    let (items, total) = s.service.list_assets(tenant, &f, &pagination).await?;
    Ok(match &caller {
        CallerContext::Staff(_) => {
            Json(PaginatedResponse::from_params(items, &pagination, total)).into_response()
        }
        CallerContext::Contact(_) => Json(PaginatedResponse::from_params(
            items
                .into_iter()
                .map(ContactAssetResponse::from)
                .collect::<Vec<_>>(),
            &pagination,
            total,
        ))
        .into_response(),
    })
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
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    // PMS-935: contact-plane callers 404 (not 403) on a foreign
    // Company's asset so a probe cannot confirm existence. PMS-1061: a
    // contact gets `ContactAssetResponse`, never the staff type.
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => assert_staff_authenticated(auth)?,
        CallerContext::Contact(_) => {
            caller.require_capability(caps::ASSETS_READ, &db).await?;
        }
    }
    let asset = s.service.get_asset(tenant, id).await?;
    Ok(match &caller {
        CallerContext::Staff(_) => Json(asset).into_response(),
        CallerContext::Contact(session) => {
            if asset.company_id != session.company_id {
                return Err(AppError::NotFound("Asset".to_string()));
            }
            Json(ContactAssetResponse::from(asset)).into_response()
        }
    })
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

/// PMS-1487: partial update sibling of `PUT /assets/{id}`.
///
/// The SPA's inline-edit drawer PATCHes one field at a time on blur;
/// the body is the subset of `AssetResponse` keys the operator changed.
/// `null` on the wire clears a nullable column; an omitted key leaves
/// it untouched. See [`PatchAssetRequest`]'s doc for the three-state
/// semantics.
async fn patch_asset(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchAssetRequest>,
) -> AppResult<Json<AssetResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.patch_asset(u.tenant(), id, u.id, &req).await?,
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
    pagination.reject_unsupported_sort()?;
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
    pagination.reject_unsupported_sort()?;
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
    pagination.reject_unsupported_sort()?;
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
    pagination.reject_unsupported_sort()?;
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

/// PMS-936: body for `POST /assets/{id}/report-issue`. Kept minimal
/// (summary + description) so the contact-plane form matches the SPA's
/// smallest possible "raise a ticket about this asset" affordance;
/// deeper fields (priority, category) live on the standard
/// ticket-create form.
#[derive(Debug, Deserialize)]
struct ReportAssetIssueBody {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// PMS-936: create a ticket linked to a specific asset.
///
/// Contact caller: gated on `assets:report_issue`, scoped to the
/// caller's Company (a foreign-Company asset 404s). The created ticket
/// carries `source = portal`, `contact_id = session.id`, and the
/// asset's `company_id` + `asset_id` so the report is discoverable
/// from the asset detail page.
///
/// Staff caller: shares the same create path; the ticket lands with
/// `contact_id = None` and `source = internal` (the default when a
/// staff caller opens a ticket without going through the contact
/// plane).
async fn report_asset_issue(
    State(s): State<AssetsRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    ctx: crate::modules::audit::AuditCtx,
    Path(asset_id): Path<Uuid>,
    Json(body): Json<ReportAssetIssueBody>,
) -> AppResult<Json<TicketResponse>> {
    let tenant = caller.tenant();
    let ticket_service = s
        .ticket_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("Ticket service not configured".to_string()))?;

    // Load the asset first so we know its Company + can fail leak-free.
    let asset = s.service.get_asset(tenant, asset_id).await?;

    let (contact_id, use_portal_path) = match &caller {
        CallerContext::Staff(auth) => {
            auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            (None, false)
        }
        CallerContext::Contact(session) => {
            caller
                .require_capability(caps::ASSETS_REPORT_ISSUE, &db)
                .await?;
            if asset.company_id != session.company_id {
                // Leak-free 404 - same posture as `get_asset`.
                return Err(AppError::NotFound("Asset".to_string()));
            }
            (Some(session.id), true)
        }
    };

    let summary_raw = body.summary.unwrap_or_default();
    let summary = summary_raw.trim();
    let title = if summary.is_empty() {
        format!("Reported issue: {}", asset.name)
    } else {
        summary.to_string()
    };
    let description = body
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    if use_portal_path {
        // Route through the shared portal-ticket path so the ticket
        // lands with `source = portal`, the tenant's default status /
        // priority / queue, and the `contact_id` stamped. The path
        // does NOT yet support arbitrary extra fields (it wraps
        // `create_ticket` with a fixed subset), so the `asset_id`
        // linkage is applied as a follow-up UPDATE below; the whole
        // report-issue flow tolerates the extra round-trip.
        let contact = contact_id.unwrap_or_else(Uuid::nil);
        let ticket = ticket_service
            .create_portal_ticket(
                tenant,
                asset.company_id,
                contact,
                title,
                description,
                None,
                None,
            )
            .await?;
        // Stamp the asset link now; the row is already
        // Company-scoped so this UPDATE cannot leak across tenants.
        // Hold the tx in a local so the explicit commit lands (a
        // dropped tx auto-rolls back and the update would silently
        // disappear).
        let mut tx = s.service.db().begin_with_tenant(tenant).await?;
        sqlx::query(
            "UPDATE tickets SET asset_id = $1, updated_at = NOW() \
             WHERE tenant_id = $2 AND id = $3",
        )
        .bind(asset_id)
        .bind(tenant.get())
        .bind(ticket.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("stamp asset_id on report-issue ticket: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("commit asset_id stamp: {e}")))?;
        // Re-fetch so the response reflects the freshly-stamped
        // `asset_id`.
        let refreshed = ticket_service
            .get_ticket_response(tenant, ticket.id)
            .await?;
        Ok(Json(refreshed))
    } else {
        // Staff branch: go through the standard `create_ticket` path
        // so the fully-populated request (with `asset_id` inline) lets
        // us skip the follow-up UPDATE. Attribute the create to the
        // caller's user id.
        let user_id = match &caller {
            CallerContext::Staff(auth) => auth.user.as_ref().map(|u| u.id).unwrap_or_default(),
            CallerContext::Contact(_) => Uuid::nil(),
        };
        let req = mokosh_types::tickets::CreateTicketRequest {
            title,
            description,
            asset_id: Some(asset_id),
            company_id: asset.company_id,
            source: mokosh_types::tickets::TicketSource::Internal,
            ..Default::default()
        };
        let ticket = ticket_service
            .create_ticket(tenant, user_id, &req, &ctx)
            .await?;
        let refreshed = ticket_service
            .get_ticket_response(tenant, ticket.id)
            .await?;
        Ok(Json(refreshed))
    }
}

// -- PMS-1486 search handlers ---------------------------------------------

/// Validate every (field, op, values) triple against the vocab in
/// `models.rs`. The service trusts what it is handed and will emit SQL
/// that misbinds on an illegal pair; the handler is where the pair is
/// refused with a 422 naming the field.
fn validate_search_request(req: &AssetSearchRequest) -> AppResult<()> {
    for (i, f) in req.filters.iter().enumerate() {
        let legal = match (f.field, f.op) {
            // ContainsTag is Tags-only.
            (AssetField::Tags, FacetOp::ContainsTag) => true,
            (AssetField::Tags, _) => false,
            (_, FacetOp::ContainsTag) => false,
            // IsNull / IsNotNull take no values; anything with values is a bug.
            (_, FacetOp::IsNull) | (_, FacetOp::IsNotNull) => f.values.is_empty(),
            // Within is a {days: N} object on date fields only.
            (
                AssetField::WarrantyExpiry
                | AssetField::EndOfLife
                | AssetField::PurchaseDate
                | AssetField::InstalledDate,
                FacetOp::Within,
            ) => f
                .values
                .first()
                .and_then(|v| v.get("days"))
                .and_then(|v| v.as_i64())
                .is_some(),
            (_, FacetOp::Within) => false,
            // Before / After on dates only.
            (
                AssetField::WarrantyExpiry
                | AssetField::EndOfLife
                | AssetField::PurchaseDate
                | AssetField::InstalledDate,
                FacetOp::Before | FacetOp::After,
            ) => f.values.len() == 1,
            (_, FacetOp::Before | FacetOp::After) => false,
            // Eq / In / NotIn: at least one value.
            (_, FacetOp::Eq) => f.values.len() == 1,
            (_, FacetOp::In | FacetOp::NotIn) => !f.values.is_empty(),
        };
        if !legal {
            return Err(AppError::validation_field(
                format!("filters[{i}]"),
                "field + op combination is not supported for this facet",
            ));
        }
    }
    Ok(())
}

fn require_search_v2(state: &AssetsRouterState) -> AppResult<()> {
    let on = state
        .features
        .as_ref()
        .is_some_and(|s| s.is_enabled(crate::modules::features::registry::Feature::AssetsSearchV2));
    if on {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "This endpoint is not enabled on this deployment".to_string(),
        ))
    }
}

async fn search_assets_structured(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Query(pagination): Query<PaginationParams>,
    Json(req): Json<AssetSearchRequest>,
) -> AppResult<Json<PaginatedResponse<AssetResponse>>> {
    require_search_v2(&s)?;
    req.validate()?;
    validate_search_request(&req)?;
    pagination.reject_unsupported_sort()?;
    let tenant = u.tenant();
    let (items, total) = s.service.search_assets(tenant, &req, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn asset_facets_structured(
    State(s): State<AssetsRouterState>,
    RequireAssets { user: u, .. }: RequireAssets,
    Json(req): Json<AssetSearchRequest>,
) -> AppResult<Json<AssetFacetsResponse>> {
    require_search_v2(&s)?;
    req.validate()?;
    validate_search_request(&req)?;
    let tenant = u.tenant();
    let resp = s.service.asset_facets(tenant, &req).await?;
    Ok(Json(resp))
}
