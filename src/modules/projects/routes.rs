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
use crate::modules::auth::{RequireAdmin, RequireAuth};
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
    RequireAuth(u): RequireAuth,
    Query(f): Query<ProjectFilter>,
    Query(p): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<ProjectResponse>>> {
    f.validate()?;
    let (items, total) = s.service.list_projects(u.tenant_id, &f, &p).await?;
    Ok(Json(PaginatedResponse::from_params(items, &p, total)))
}

async fn create_project(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Json(req): Json<CreateProjectRequest>,
) -> AppResult<Json<ProjectResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_project(u.tenant_id, &req).await?))
}

async fn get_project(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ProjectResponse>> {
    Ok(Json(s.service.get_project(u.tenant_id, id).await?))
}

async fn update_project(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateProjectRequest>,
) -> AppResult<Json<ProjectResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_project(u.tenant_id, id, &req).await?))
}

async fn delete_project(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_project(u.tenant_id, id).await
}

async fn list_project_phases(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<ProjectPhaseResponse>>> {
    Ok(Json(s.service.list_project_phases(u.tenant_id, id).await?))
}

async fn create_project_phase(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertProjectPhaseRequest>,
) -> AppResult<Json<ProjectPhaseResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .create_project_phase(u.tenant_id, id, &req)
            .await?,
    ))
}

async fn update_project_phase(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(phase_id): Path<Uuid>,
    Json(req): Json<UpsertProjectPhaseRequest>,
) -> AppResult<Json<ProjectPhaseResponse>> {
    req.validate()?;
    Ok(Json(
        s.service
            .update_project_phase(u.tenant_id, phase_id, &req)
            .await?,
    ))
}

async fn delete_project_phase(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(phase_id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_project_phase(u.tenant_id, phase_id).await
}

async fn list_task_statuses(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
) -> AppResult<Json<Vec<TaskStatusResponse>>> {
    Ok(Json(s.service.list_task_statuses(u.tenant_id).await?))
}

async fn create_task_status(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Json(req): Json<UpsertTaskStatusRequest>,
) -> AppResult<Json<TaskStatusResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_task_status(u.tenant_id, &req).await?))
}

async fn update_task_status(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(req): Json<UpsertTaskStatusRequest>,
) -> AppResult<Json<TaskStatusResponse>> {
    req.validate()?;
    Ok(Json(
        s.service.update_task_status(u.tenant_id, id, &req).await?,
    ))
}

async fn delete_task_status(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_task_status(u.tenant_id, id).await
}

async fn list_project_tasks(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<TaskResponse>>> {
    Ok(Json(s.service.list_project_tasks(u.tenant_id, id).await?))
}

async fn create_task(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateTaskRequest>,
) -> AppResult<Json<TaskResponse>> {
    req.validate()?;
    Ok(Json(s.service.create_task(u.tenant_id, id, &req).await?))
}

async fn get_task(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<Json<TaskResponse>> {
    Ok(Json(s.service.get_task(u.tenant_id, id).await?))
}

async fn update_task(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTaskRequest>,
) -> AppResult<Json<TaskResponse>> {
    req.validate()?;
    Ok(Json(s.service.update_task(u.tenant_id, id, &req).await?))
}

async fn delete_task(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    s.service.delete_task(u.tenant_id, id).await
}

async fn add_dep(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path((id, other)): Path<(Uuid, Uuid)>,
) -> AppResult<()> {
    s.service.add_task_dependency(u.tenant_id, id, other).await
}

async fn remove_dep(
    State(s): State<ProjectsRouterState>,
    RequireAuth(u): RequireAuth,
    Path((id, other)): Path<(Uuid, Uuid)>,
) -> AppResult<()> {
    s.service
        .remove_task_dependency(u.tenant_id, id, other)
        .await
}
