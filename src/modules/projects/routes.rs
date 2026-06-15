//! Projects HTTP routes.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::ProjectsService;
use crate::modules::auth::{RequireAdmin, RequireProjects, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct ProjectsRouterState {
    pub service: Arc<ProjectsService>,
}

pub fn projects_routes(service: ProjectsService) -> Router {
    let state = ProjectsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        // PMS-53 projects
        .route("/projects", get(list_projects).post(create_project))
        .route(
            "/projects/{id}",
            get(get_project).put(update_project).delete(delete_project),
        )
        // PMS-54 phases
        .route(
            "/projects/{id}/phases",
            get(list_project_phases).post(create_project_phase),
        )
        .route(
            "/phases/{phase_id}",
            put(update_project_phase).delete(delete_project_phase),
        )
        // PMS-55 task statuses
        .route(
            "/task-statuses",
            get(list_task_statuses).post(create_task_status),
        )
        .route(
            "/task-statuses/{id}",
            put(update_task_status).delete(delete_task_status),
        )
        // PMS-322 project types
        .route(
            "/project-types",
            get(list_project_types).post(create_project_type),
        )
        .route(
            "/project-types/{id}",
            put(update_project_type).delete(delete_project_type),
        )
        // PMS-56 tasks
        .route(
            "/projects/{id}/tasks",
            get(list_project_tasks).post(create_task),
        )
        .route(
            "/tasks/{id}",
            get(get_task).put(update_task).delete(delete_task),
        )
        // PMS-57 task dependencies
        .route(
            "/tasks/{id}/depends-on/{other}",
            post(add_dep).delete(remove_dep),
        )
        .with_state(state)
}

async fn list_projects(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Query(f): Query<ProjectFilter>,
    Query(p): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ProjectResponse>>> {
    f.validate()?;
    let (items, total) = s.service.list_projects(u.tenant(), &f, &p).await?;
    Ok(Json(PaginatedResponse::from_params(items, &p, total)))
}

async fn create_project(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Json(req): Json<CreateProjectRequest>,
) -> AppResult<Json<ProjectResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_project(u.tenant(), &req).await?))
}

async fn get_project(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ProjectResponse>> {
    Ok(Json(s.service.get_project(u.tenant(), id).await?))
}

async fn update_project(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateProjectRequest>,
) -> AppResult<Json<ProjectResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_project(u.tenant(), id, &req, &ctx).await?,
    ))
}

async fn delete_project(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_project(u.tenant(), id).await
}

async fn list_project_phases(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ProjectPhaseResponse>>> {
    let (items, total) = s
        .service
        .list_project_phases(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_project_phase(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertProjectPhaseRequest>,
) -> AppResult<Json<ProjectPhaseResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.create_project_phase(u.tenant(), id, &req).await?,
    ))
}

async fn update_project_phase(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(phase_id): Path<Uuid>,
    Json(req): Json<UpsertProjectPhaseRequest>,
) -> AppResult<Json<ProjectPhaseResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_project_phase(u.tenant(), phase_id, &req)
            .await?,
    ))
}

async fn delete_project_phase(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(phase_id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_project_phase(u.tenant(), phase_id).await
}

async fn list_task_statuses(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TaskStatusResponse>>> {
    let (items, total) = s
        .service
        .list_task_statuses(u.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_task_status(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    _a: RequireAdmin,
    Json(req): Json<UpsertTaskStatusRequest>,
) -> AppResult<Json<TaskStatusResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_task_status(u.tenant(), &req).await?))
}

async fn update_task_status(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertTaskStatusRequest>,
) -> AppResult<Json<TaskStatusResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_task_status(u.tenant(), id, &req).await?,
    ))
}

async fn delete_task_status(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_task_status(u.tenant(), id).await
}

// PMS-322 project types. Reads need only project access; mutations are
// admin-gated, mirroring task-statuses.
async fn list_project_types(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ProjectTypeResponse>>> {
    let (items, total) = s
        .service
        .list_project_types(u.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_project_type(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    _a: RequireAdmin,
    Json(req): Json<UpsertProjectTypeRequest>,
) -> AppResult<Json<ProjectTypeResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_project_type(u.tenant(), &req).await?))
}

async fn update_project_type(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertProjectTypeRequest>,
) -> AppResult<Json<ProjectTypeResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_project_type(u.tenant(), id, &req).await?,
    ))
}

async fn delete_project_type(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_project_type(u.tenant(), id).await
}

async fn list_project_tasks(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TaskResponse>>> {
    let (items, total) = s
        .service
        .list_project_tasks(u.tenant(), id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

async fn create_task(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateTaskRequest>,
) -> AppResult<Json<TaskResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_task(u.tenant(), id, &req).await?))
}

async fn get_task(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(id): Path<Uuid>,
) -> AppResult<Json<TaskResponse>> {
    Ok(Json(s.service.get_task(u.tenant(), id).await?))
}

async fn update_task(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    ctx: crate::modules::audit::AuditCtx,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTaskRequest>,
) -> AppResult<Json<TaskResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_task(u.tenant(), id, &req, &ctx).await?,
    ))
}

async fn delete_task(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_task(u.tenant(), id).await
}

async fn add_dep(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path((id, other)): Path<(Uuid, Uuid)>,
) -> AppResult<()> {
    s.service.add_task_dependency(u.tenant(), id, other).await
}

async fn remove_dep(
    State(s): State<ProjectsRouterState>,
    RequireProjects { user: u, .. }: RequireProjects,
    Path((id, other)): Path<(Uuid, Uuid)>,
) -> AppResult<()> {
    s.service
        .remove_task_dependency(u.tenant(), id, other)
        .await
}
