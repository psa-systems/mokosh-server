//! Ticket API routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    CreateNoteRequest, CreateTicketRequest, TicketFilter, TicketNoteResponse, TicketPriority,
    TicketQueue, TicketResponse, TicketService, TicketStatus, TicketType, UpdateTicketRequest,
};
use crate::modules::auth::{RequireAuth, TenantScoped};
use crate::utils::error::AppResult;
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct TicketRouterState {
    pub ticket_service: Arc<TicketService>,
}

/// Create the ticket router
pub fn ticket_routes(ticket_service: TicketService) -> Router {
    let state = TicketRouterState {
        ticket_service: Arc::new(ticket_service),
    };

    Router::new()
        // Tickets
        .route("/", get(list_tickets))
        .route("/", post(create_ticket))
        .route("/{ticket_id}", get(get_ticket))
        .route("/{ticket_id}", put(update_ticket))
        .route("/{ticket_id}", delete(delete_ticket))
        .route("/{ticket_id}/assign", post(assign_ticket))
        .route("/{ticket_id}/notes", get(get_ticket_notes))
        .route("/{ticket_id}/notes", post(add_note))
        // Configuration
        .route("/statuses", get(get_statuses))
        .route("/priorities", get(get_priorities))
        .route("/queues", get(get_queues))
        .route("/types", get(get_types))
        .with_state(state)
}

async fn list_tickets(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Query(filter): Query<TicketFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketResponse>>> {
    // F9: validate filter inputs.
    filter.validate()?;
    let (responses, total) = state
        .ticket_service
        .list_ticket_responses(user.tenant(), &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        responses,
        &pagination,
        total,
    )))
}

async fn create_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;
    let ticket = state
        .ticket_service
        .create_ticket(user.tenant(), user.id, &request, &ctx)
        .await?;
    let resp = state
        .ticket_service
        .get_ticket_response(user.tenant(), ticket.id)
        .await?;
    Ok(Json(resp))
}

async fn get_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<TicketResponse>> {
    let resp = state
        .ticket_service
        .get_ticket_response(user.tenant(), ticket_id)
        .await?;
    Ok(Json(resp))
}

async fn update_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<UpdateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;
    state
        .ticket_service
        .update_ticket(user.tenant(), ticket_id, user.id, &request, &ctx)
        .await?;
    let resp = state
        .ticket_service
        .get_ticket_response(user.tenant(), ticket_id)
        .await?;
    Ok(Json(resp))
}

async fn delete_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    ctx: crate::modules::audit::AuditCtx,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<()> {
    state
        .ticket_service
        .delete_ticket(user.tenant(), ticket_id, &ctx)
        .await
}

#[derive(serde::Deserialize)]
struct AssignRequest {
    assigned_to_id: Uuid,
}

async fn assign_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<AssignRequest>,
) -> AppResult<Json<TicketResponse>> {
    state
        .ticket_service
        .assign_ticket(user.tenant(), ticket_id, request.assigned_to_id, user.id)
        .await?;
    let resp = state
        .ticket_service
        .get_ticket_response(user.tenant(), ticket_id)
        .await?;
    Ok(Json(resp))
}

async fn get_ticket_notes(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketNoteResponse>>> {
    let (notes, total) = state
        .ticket_service
        .get_ticket_notes(user.tenant(), ticket_id, &pagination)
        .await?;

    let responses: Vec<TicketNoteResponse> = notes
        .into_iter()
        .map(|n| TicketNoteResponse {
            id: n.id,
            note_type: n.note_type,
            content: n.content,
            is_email_sent: n.is_email_sent,
            created_by_id: n.created_by_id,
            created_by_name: n.created_by_name.unwrap_or_default(),
            created_at: n.created_at,
        })
        .collect();

    Ok(Json(PaginatedResponse::from_params(
        responses,
        &pagination,
        total,
    )))
}

async fn add_note(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<CreateNoteRequest>,
) -> AppResult<Json<TicketNoteResponse>> {
    request.validate()?;

    let note = state
        .ticket_service
        .add_note(user.tenant(), ticket_id, user.id, &request)
        .await?;

    Ok(Json(TicketNoteResponse {
        id: note.id,
        note_type: note.note_type,
        content: note.content,
        is_email_sent: note.is_email_sent,
        created_by_id: note.created_by_id,
        created_by_name: note.created_by_name.unwrap_or_else(|| user.full_name()),
        created_at: note.created_at,
    }))
}

async fn get_statuses(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketStatus>>> {
    let (statuses, total) = state
        .ticket_service
        .get_statuses(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        statuses,
        &pagination,
        total,
    )))
}

async fn get_priorities(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketPriority>>> {
    let (priorities, total) = state
        .ticket_service
        .get_priorities(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        priorities,
        &pagination,
        total,
    )))
}

async fn get_queues(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketQueue>>> {
    let (queues, total) = state
        .ticket_service
        .get_queues(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        queues,
        &pagination,
        total,
    )))
}

async fn get_types(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketType>>> {
    let (types, total) = state
        .ticket_service
        .get_types(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        types,
        &pagination,
        total,
    )))
}
