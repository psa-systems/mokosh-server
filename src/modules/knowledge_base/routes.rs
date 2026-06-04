//! Knowledge base HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::KbService;
use crate::modules::auth::{RequireAuth, RequireManager};
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
        // Portal-visible (PMS-84). Internal callers can still reach this;
        // the portal mounts its own thin reader in PMS-32.
        .route("/kb/articles/portal", get(list_portal_articles))
        .with_state(state)
}

async fn list_categories(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbCategoryResponse>>> {
    let (items, total) = s.service.list_categories(u.tenant_id, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_category(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Json(req): Json<UpsertKbCategoryRequest>,
) -> AppResult<Json<KbCategoryResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_category(u.tenant_id, &req).await?))
}

async fn update_category(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertKbCategoryRequest>,
) -> AppResult<Json<KbCategoryResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_category(u.tenant_id, id, &req).await?,
    ))
}

async fn delete_category(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_category(u.tenant_id, id).await
}

async fn list_articles(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    Query(f): Query<KbArticleFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbArticleResponse>>> {
    f.validate()?;
    let (items, total) = s
        .service
        .list_articles(u.tenant_id, &f, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_article(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<CreateKbArticleRequest>,
) -> AppResult<Json<KbArticleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_article(u.tenant_id, u.id, &req).await?,
    ))
}

async fn get_article(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KbArticleResponse>> {
    Ok(Json(s.service.get_article(u.tenant_id, id).await?))
}

async fn update_article(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateKbArticleRequest>,
) -> AppResult<Json<KbArticleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_article(u.tenant_id, id, u.id, &req)
            .await?,
    ))
}

async fn delete_article(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_article(u.tenant_id, id).await
}

async fn list_article_versions(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbArticleVersionResponse>>> {
    let (items, total) = s
        .service
        .list_article_versions(u.tenant_id, id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn list_portal_articles(
    State(s): State<KbRouterState>,
    RequireAuth(u): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbArticleResponse>>> {
    let (items, total) = s
        .service
        .list_portal_articles(u.tenant_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}
