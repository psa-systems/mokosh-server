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
use crate::db::Database;
use crate::modules::auth::{
    CallerContext, RequireCallerContext, RequireKnowledgeBase, RequireManager, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
use crate::modules::settings::SettingsService;
use crate::utils::error::{AppError, AppResult};
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
        // PMS-922: the author's in-progress text. Deliberately its own
        // resource rather than a flag on the article PUT: `update_article`
        // snapshots a version on every call, so autosaving through it would
        // append a revision per interval and bury the real edits.
        .route(
            "/kb/articles/{id}/draft",
            get(get_draft).put(save_draft).delete(delete_draft),
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
        // PMS-485: "Top ticket-driving articles" widget on the KB
        // landing page. Tenant-scoped GROUP BY over tickets joined
        // to kb_articles on the PMS-452 `source_kb_article_id` FK.
        .route(
            "/kb/top-ticket-driving-articles",
            get(list_top_ticket_driving_articles),
        )
        // PMS-732: what the tracked time says this article's request type
        // actually takes. A sub-resource rather than a field on the article
        // response, so it is never a sometimes-populated key: computing it for
        // every row of a list would join the whole time table, and a field
        // that is real on GET-one and always null on GET-many is exactly the
        // shallow-DTO trap docs/dev-docs/codebase-state.md warns about.
        .route(
            "/kb/articles/{id}/measured-duration",
            get(article_measured_duration),
        )
        // PMS-1082: the three reads above (`GET /kb/categories`,
        // `GET /kb/articles`, `GET /kb/articles/{id}`) are dual-plane
        // (`RequireCallerContext`): a contact holding `kb:read` gets the
        // published, Company-visible slice through them, which is what
        // the SPA's Knowledge Base nav calls. Everything else on this
        // tree stays behind `RequireKnowledgeBase`, which a contact
        // bearer never satisfies.
        .with_state(state)
}

async fn list_categories(
    State(s): State<KbRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    axum::extract::Extension(settings): axum::extract::Extension<Arc<SettingsService>>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<KbCategoryResponse>>> {
    // PMS-1082: a contact with `kb:read` sees the non-internal
    // categories; staff keep the module gate they had.
    let tenant = caller.tenant();
    let (items, total) = match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_kb_enabled(auth, &settings).await?;
            s.service.list_categories(tenant, &pagination).await?
        }
        CallerContext::Contact(_) => {
            caller.require_capability(caps::KB_READ, &db).await?;
            s.service
                .list_categories_for_contact(tenant, &pagination)
                .await?
        }
    };
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

/// PMS-1082: the staff arm of a dual-plane KB read keeps exactly the
/// surface `RequireKnowledgeBase` gave it: an authenticated staff
/// user AND the tenant's `knowledge_base` module on, else the same
/// 404 the extractor answers. The contact arm deliberately does not
/// consult the module flag: `kb:read` on the contact's role is the
/// authorization signal there (the PMS-935 rule), and the flag is
/// the MSP's staff-side toggle.
async fn assert_staff_kb_enabled(
    auth: &crate::modules::auth::AuthState,
    settings: &SettingsService,
) -> AppResult<()> {
    let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
    if !settings
        .is_module_enabled(user.tenant(), "knowledge_base")
        .await?
    {
        return Err(AppError::NotFound("Knowledge base module".to_string()));
    }
    Ok(())
}

async fn create_category(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<UpsertKbCategoryRequest>,
) -> AppResult<Json<KbCategoryResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_category(u.tenant(), &req, &ctx).await?,
    ))
}

async fn update_category(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertKbCategoryRequest>,
) -> AppResult<Json<KbCategoryResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_category(u.tenant(), id, &req).await?))
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
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    axum::extract::Extension(settings): axum::extract::Extension<Arc<SettingsService>>,
    Query(f): Query<KbArticleFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    f.validate()?;
    // PMS-1082: dual-plane. The contact arm requires `kb:read`
    // (DB-loaded per request, the JWT `caps` claim is UI-only) and is
    // scoped by the session's Company to the published, visible slice;
    // its `status` and `visibility` params are ignored by the service.
    // PMS-1061: it answers with `ContactKbArticleResponse`, never the
    // staff type.
    let tenant = caller.tenant();
    Ok(match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_kb_enabled(auth, &settings).await?;
            let (items, total) = s.service.list_articles(tenant, &f, &pagination).await?;
            Json(PaginatedResponse::from_params(items, &pagination, total)).into_response()
        }
        CallerContext::Contact(session) => {
            caller.require_capability(caps::KB_READ, &db).await?;
            let (items, total) = s
                .service
                .list_articles_for_contact(tenant, session.company_id, &f, &pagination)
                .await?;
            Json(PaginatedResponse::from_params(
                items
                    .into_iter()
                    .map(ContactKbArticleResponse::from)
                    .collect::<Vec<_>>(),
                &pagination,
                total,
            ))
            .into_response()
        }
    })
}

async fn create_article(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    ctx: crate::modules::audit::AuditCtx,
    Json(req): Json<CreateKbArticleRequest>,
) -> AppResult<Json<KbArticleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_article(u.tenant(), u.id, &req, &ctx)
            .await?,
    ))
}

async fn get_article(
    State(s): State<KbRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    axum::extract::Extension(settings): axum::extract::Extension<Arc<SettingsService>>,
    Path(id): Path<Uuid>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    // PMS-1082: a contact reads through `get_portal_article`, whose
    // WHERE clause carries the visibility rule, so an internal
    // article, a draft and another Company's `client_specific`
    // article all 404 exactly as an unknown id does, and the staff
    // `view_count` is not bumped by a customer's read.
    let tenant = caller.tenant();
    Ok(match &caller {
        CallerContext::Staff(auth) => {
            assert_staff_kb_enabled(auth, &settings).await?;
            Json(s.service.get_article(tenant, id).await?).into_response()
        }
        CallerContext::Contact(session) => {
            caller.require_capability(caps::KB_READ, &db).await?;
            let article = s
                .service
                .get_portal_article(tenant, session.company_id, id)
                .await?;
            Json(ContactKbArticleResponse::from(article)).into_response()
        }
    })
}

async fn update_article(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateKbArticleRequest>,
) -> AppResult<Json<KbArticleResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_article(u.tenant(), id, u.id, &req, &ctx)
            .await?,
    ))
}

/// PMS-922: upsert the caller's draft.
///
/// `RequireManager` like the article PUT it is a draft of: a draft is
/// in-progress editing, so whoever can save can draft, and nobody else can use
/// it as a side door. `RequireKnowledgeBase` still gates the module.
async fn save_draft(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Path(id): Path<Uuid>,
    Json(req): Json<SaveKbDraftRequest>,
) -> AppResult<Json<KbDraftResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.save_draft(u.tenant(), id, u.id, &req).await?,
    ))
}

/// The caller's draft, or 404 when they have none.
///
/// 404 rather than 200-with-null so "no draft" is a status the client can
/// branch on without inspecting a body, and so it reads the same as any other
/// absent resource.
async fn get_draft(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<Json<KbDraftResponse>> {
    s.service
        .get_draft(u.tenant(), id, u.id)
        .await?
        .map(Json)
        .ok_or_else(|| crate::utils::error::AppError::NotFound("Draft".to_string()))
}

async fn delete_draft(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    Path(id): Path<Uuid>,
) -> AppResult<axum::http::StatusCode> {
    s.service.delete_draft(u.tenant(), id, u.id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn delete_article(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_article(u.tenant(), id, &ctx).await
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

/// PMS-1126: `RequireManager` like the article PUT it is a form of. Before
/// this the route carried only the module gate, so a technician who could
/// not edit an article could still rewrite it to any past version. Takes an
/// optional `{ "change_note" }` (an absent or empty body is `{}`) and
/// answers the version the restore wrote rather than the article, because
/// that row, with its `restored_from_version`, is what the caller asked
/// for; the article itself is one GET away and the client re-reads it
/// anyway.
async fn restore_article_version(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    _m: RequireManager,
    ctx: crate::modules::audit::AuditCtx,
    Path((id, version_number)): Path<(Uuid, i32)>,
    body: Option<Json<RestoreKbArticleVersionRequest>>,
) -> AppResult<Json<KbArticleVersionResponse>> {
    let req = body.map(|Json(r)| r).unwrap_or_default();
    req.validate()?;
    Ok(Json(
        s.service
            .restore_article_version(u.tenant(), id, version_number, u.id, &req, &ctx)
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

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TopTicketDrivingQuery {
    /// Days to look back; defaults to 90, capped at 365 to keep the
    /// scan bounded on long-lived tenants.
    #[serde(default)]
    pub days: Option<i64>,
    /// Row cap; defaults to 20, max 100.
    #[serde(default)]
    pub limit: Option<i64>,
}

async fn list_top_ticket_driving_articles(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Query(q): Query<TopTicketDrivingQuery>,
) -> AppResult<Json<Vec<TopTicketDrivingArticleRow>>> {
    let days = q.days.unwrap_or(90).clamp(1, 365);
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let since = chrono::Utc::now() - chrono::Duration::days(days);
    Ok(Json(
        s.service
            .list_top_ticket_driving_articles(u.tenant(), since, limit)
            .await?,
    ))
}

#[derive(Debug, serde::Deserialize)]
struct MeasuredDurationQuery {
    from: Option<chrono::NaiveDate>,
    to: Option<chrono::NaiveDate>,
}

async fn article_measured_duration(
    State(s): State<KbRouterState>,
    RequireKnowledgeBase { user: u, .. }: RequireKnowledgeBase,
    Path(id): Path<Uuid>,
    Query(q): Query<MeasuredDurationQuery>,
) -> AppResult<Json<super::service::ArticleMeasuredDuration>> {
    Ok(Json(
        s.service
            .measured_duration(u.tenant(), id, q.from, q.to)
            .await?,
    ))
}
