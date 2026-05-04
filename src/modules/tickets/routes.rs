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
use crate::modules::auth::RequireAuth;
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
        .route("/:ticket_id", get(get_ticket))
        .route("/:ticket_id", put(update_ticket))
        .route("/:ticket_id/assign", post(assign_ticket))
        .route("/:ticket_id/notes", get(get_ticket_notes))
        .route("/:ticket_id/notes", post(add_note))
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
    let (tickets, total) = state
        .ticket_service
        .list_tickets(user.tenant_id, &filter, &pagination)
        .await?;

    // Convert to response format with related data
    let responses: Vec<TicketResponse> = tickets
        .into_iter()
        .map(|t| {
            let sla_status = t.sla_status();
            TicketResponse {
                id: t.id,
                ticket_number: t.ticket_number,
                title: t.title,
                description: t.description,
                status: super::TicketStatusSummary {
                    id: t.status_id,
                    name: String::new(), // Would be joined from DB
                    color: String::new(),
                    is_closed: false,
                },
                priority: super::TicketPrioritySummary {
                    id: t.priority_id,
                    name: String::new(),
                    color: String::new(),
                },
                type_name: None,
                category_name: None,
                queue_name: String::new(),
                source: t.source,
                company_id: t.company_id,
                company_name: String::new(),
                contact_id: t.contact_id,
                contact_name: None,
                assigned_to_id: t.assigned_to_id,
                assigned_to_name: None,
                sla_due_date: t.sla_due_date,
                sla_status,
                is_billable: t.is_billable,
                billing_status: t.billing_status,
                estimated_hours: t.estimated_hours,
                actual_hours: t.actual_hours,
                tags: t.tags,
                created_by_name: String::new(),
                created_at: t.created_at,
                updated_at: t.updated_at,
            }
        })
        .collect();

    let response = PaginatedResponse::from_params(responses, &pagination, total);

    Ok(Json(response))
}

async fn create_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Json(request): Json<CreateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;

    let ticket = state
        .ticket_service
        .create_ticket(user.tenant_id, user.id, &request)
        .await?;

    // Convert to response
    let sla_status = ticket.sla_status();
    Ok(Json(TicketResponse {
        id: ticket.id,
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        description: ticket.description,
        status: super::TicketStatusSummary {
            id: ticket.status_id,
            name: String::new(),
            color: String::new(),
            is_closed: false,
        },
        priority: super::TicketPrioritySummary {
            id: ticket.priority_id,
            name: String::new(),
            color: String::new(),
        },
        type_name: None,
        category_name: None,
        queue_name: String::new(),
        source: ticket.source,
        company_id: ticket.company_id,
        company_name: String::new(),
        contact_id: ticket.contact_id,
        contact_name: None,
        assigned_to_id: ticket.assigned_to_id,
        assigned_to_name: None,
        sla_due_date: ticket.sla_due_date,
        sla_status,
        is_billable: ticket.is_billable,
        billing_status: ticket.billing_status,
        estimated_hours: ticket.estimated_hours,
        actual_hours: ticket.actual_hours,
        tags: ticket.tags,
        created_by_name: user.full_name(),
        created_at: ticket.created_at,
        updated_at: ticket.updated_at,
    }))
}

async fn get_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<TicketResponse>> {
    let ticket = state
        .ticket_service
        .get_ticket(user.tenant_id, ticket_id)
        .await?;

    let sla_status = ticket.sla_status();
    Ok(Json(TicketResponse {
        id: ticket.id,
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        description: ticket.description,
        status: super::TicketStatusSummary {
            id: ticket.status_id,
            name: String::new(),
            color: String::new(),
            is_closed: false,
        },
        priority: super::TicketPrioritySummary {
            id: ticket.priority_id,
            name: String::new(),
            color: String::new(),
        },
        type_name: None,
        category_name: None,
        queue_name: String::new(),
        source: ticket.source,
        company_id: ticket.company_id,
        company_name: String::new(),
        contact_id: ticket.contact_id,
        contact_name: None,
        assigned_to_id: ticket.assigned_to_id,
        assigned_to_name: None,
        sla_due_date: ticket.sla_due_date,
        sla_status,
        is_billable: ticket.is_billable,
        billing_status: ticket.billing_status,
        estimated_hours: ticket.estimated_hours,
        actual_hours: ticket.actual_hours,
        tags: ticket.tags,
        created_by_name: String::new(),
        created_at: ticket.created_at,
        updated_at: ticket.updated_at,
    }))
}

async fn update_ticket(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<UpdateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;

    let ticket = state
        .ticket_service
        .update_ticket(user.tenant_id, ticket_id, user.id, &request)
        .await?;

    let sla_status = ticket.sla_status();
    Ok(Json(TicketResponse {
        id: ticket.id,
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        description: ticket.description,
        status: super::TicketStatusSummary {
            id: ticket.status_id,
            name: String::new(),
            color: String::new(),
            is_closed: false,
        },
        priority: super::TicketPrioritySummary {
            id: ticket.priority_id,
            name: String::new(),
            color: String::new(),
        },
        type_name: None,
        category_name: None,
        queue_name: String::new(),
        source: ticket.source,
        company_id: ticket.company_id,
        company_name: String::new(),
        contact_id: ticket.contact_id,
        contact_name: None,
        assigned_to_id: ticket.assigned_to_id,
        assigned_to_name: None,
        sla_due_date: ticket.sla_due_date,
        sla_status,
        is_billable: ticket.is_billable,
        billing_status: ticket.billing_status,
        estimated_hours: ticket.estimated_hours,
        actual_hours: ticket.actual_hours,
        tags: ticket.tags,
        created_by_name: String::new(),
        created_at: ticket.created_at,
        updated_at: ticket.updated_at,
    }))
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
    let ticket = state
        .ticket_service
        .assign_ticket(user.tenant_id, ticket_id, request.assigned_to_id, user.id)
        .await?;

    let sla_status = ticket.sla_status();
    Ok(Json(TicketResponse {
        id: ticket.id,
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        description: ticket.description,
        status: super::TicketStatusSummary {
            id: ticket.status_id,
            name: String::new(),
            color: String::new(),
            is_closed: false,
        },
        priority: super::TicketPrioritySummary {
            id: ticket.priority_id,
            name: String::new(),
            color: String::new(),
        },
        type_name: None,
        category_name: None,
        queue_name: String::new(),
        source: ticket.source,
        company_id: ticket.company_id,
        company_name: String::new(),
        contact_id: ticket.contact_id,
        contact_name: None,
        assigned_to_id: ticket.assigned_to_id,
        assigned_to_name: None,
        sla_due_date: ticket.sla_due_date,
        sla_status,
        is_billable: ticket.is_billable,
        billing_status: ticket.billing_status,
        estimated_hours: ticket.estimated_hours,
        actual_hours: ticket.actual_hours,
        tags: ticket.tags,
        created_by_name: String::new(),
        created_at: ticket.created_at,
        updated_at: ticket.updated_at,
    }))
}

async fn get_ticket_notes(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<Vec<TicketNoteResponse>>> {
    let notes = state
        .ticket_service
        .get_ticket_notes(user.tenant_id, ticket_id)
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

    Ok(Json(responses))
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
        .add_note(user.tenant_id, ticket_id, user.id, &request)
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
) -> AppResult<Json<Vec<TicketStatus>>> {
    let statuses = state.ticket_service.get_statuses(user.tenant_id).await?;
    Ok(Json(statuses))
}

async fn get_priorities(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<TicketPriority>>> {
    let priorities = state.ticket_service.get_priorities(user.tenant_id).await?;
    Ok(Json(priorities))
}

async fn get_queues(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<TicketQueue>>> {
    let queues = state.ticket_service.get_queues(user.tenant_id).await?;
    Ok(Json(queues))
}

async fn get_types(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
) -> AppResult<Json<Vec<TicketType>>> {
    let types = state.ticket_service.get_types(user.tenant_id).await?;
    Ok(Json(types))
}
