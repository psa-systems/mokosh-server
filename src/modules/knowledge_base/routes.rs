//! Knowledge base HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::KbService;
use crate::modules::auth::{RequireKnowledgeBase, RequireManager, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct KbRouterState {
    pub service: Arc<KbService>,
}

pub fn kb_routes(service: KbService) -> Router {
    let state = KbRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // Categories (PMS-81)
        .route("/kb/categories", get(list_categories).post(create_category))
        .route(
            "/kb/categories/{id}",
            put(update_category).delete(delete_category),
        )
        // Articles (PMS-82) + versions (PMS-83)
        .route("/kb/articles", get(list_articles).post(create_article))
        .route(
            "/kb/articles/{id}",
            get(get_article).put(update_article).delete(delete_article),
        )
        .route("/kb/articles/{id}/versions", get(list_article_versions))
        // Restore a prior version as a new monotonic version (PMS-83).
        .route(
            "/kb/articles/{id}/versions/{version_number}/restore",
            post(restore_article_version),
        )
        // Feedback votes (PMS-84). Tenant-scoped, one vote per user
        // account, mutually exclusive (helpful XOR not_helpful) and
        // toggleable: POST records / toggles the caller's vote and
        // returns the recomputed tallies plus the caller's resulting
        // `my_vote`. GET reads the caller's current vote + counts without
        // mutating, so the detail page can render the active thumb on load.
        .route("/kb/articles/{id}/helpful", post(mark_helpful))
        .route("/kb/articles/{id}/not_helpful", post(mark_not_helpful))
        .route("/kb/articles/{id}/vote", get(get_article_vote))
        // The portal-visible feed lives on the portal tree at
        // `GET /api/v1/portal/kb`, behind `PortalAuthMiddleware` /
        // `RequirePortalAuth` and scoped to the authenticated contact's
        // tenant + company (`KbService::list_portal_articles_for_company`).
        // It is intentionally NOT mounted here: this agent tree carries
        // only `RequireKnowledgeBase` (agent) auth, so a route named
        // "portal" here would either be unreachable by portal tokens or,
        // worse, expose the portal feed under agent auth that trusts the
        // caller's own tenant rather than the portal contact's. See
        // `modules/portal/routes.rs::list_kb`.
        .with_state(state)
}

async fn list_categories(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbCategoryResponse>>> {
    let (items, total) = s.service.list_categories(u.tenant(), &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_category(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Json(req): Json<UpsertKbCategoryRequest>,
) -> AppResult<Json<KbCategoryResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_category(u.tenant(), &req).await?))
}

async fn update_category(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertKbCategoryRequest>,
) -> AppResult<Json<KbCategoryResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_category(u.tenant(), id, &req).await?,
    ))
}

async fn delete_category(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_category(u.tenant(), id).await
}

async fn list_articles(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Query(f): Query<KbArticleFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbArticleResponse>>> {
    f.validate()?;
    let (items, total) = s
        .service
        .list_articles(u.tenant(), &f, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_article(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Json(req): Json<CreateKbArticleRequest>,
) -> AppResult<Json<KbArticleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_article(u.tenant(), u.id, &req).await?,
    ))
}

async fn get_article(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KbArticleResponse>> {
    Ok(Json(s.service.get_article(u.tenant(), id).await?))
}

async fn update_article(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateKbArticleRequest>,
) -> AppResult<Json<KbArticleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_article(u.tenant(), id, u.id, &req)
            .await?,
    ))
}

async fn delete_article(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_article(u.tenant(), id).await
}

async fn list_article_versions(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbArticleVersionResponse>>> {
    let (items, total) = s
        .service
        .list_article_versions(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn restore_article_version(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path((id, version_number)): Path<(Uuid, i32)>,
) -> AppResult<Json<KbArticleResponse>> {
    Ok(Json(
        s.service
            .restore_article_version(u.tenant(), id, version_number, u.id)
            .await?,
    ))
}

async fn mark_helpful(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KbArticleFeedbackResponse>> {
    Ok(Json(
        s.service.increment_helpful(u.tenant(), id, u.id).await?,
    ))
}

async fn mark_not_helpful(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KbArticleFeedbackResponse>> {
    Ok(Json(
        s.service
            .increment_not_helpful(u.tenant(), id, u.id)
            .await?,
    ))
}

async fn get_article_vote(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KbArticleFeedbackResponse>> {
    Ok(Json(
        s.service.get_article_vote(u.tenant(), id, u.id).await?,
    ))
}
