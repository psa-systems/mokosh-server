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
    CreateNoteRequest, CreateTicketRequest, NoteType, TicketCategoryResponse, TicketFilter,
    TicketNoteResponse, TicketPriority, TicketQueue, TicketResponse, TicketService, TicketStatus,
    TicketType, UpdateTicketRequest, UpsertTicketCategoryRequest, UpsertTicketPriorityRequest,
    UpsertTicketQueueRequest, UpsertTicketStatusRequest, UpsertTicketTypeRequest,
};
use crate::db::Database;
use crate::modules::auth::{
    CallerContext, RequireAdmin, RequireAuth, RequireCallerContext, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct TicketRouterState {
    pub ticket_service: Arc<TicketService>,
}

/// PMS-468: build a sibling router for the agent "all comments
/// from this contact" feed. Mounted at `/api/v1/contacts/{id}/notes`
/// alongside the main contacts router so the path matches the SPA's
/// contact-detail URL. Returns the TicketService-backed router as a
/// standalone `Router` because the contacts module's router state
/// holds the ContactService, not the TicketService.
pub fn contact_notes_routes(ticket_service: TicketService) -> Router {
    let state = TicketRouterState {
        ticket_service: Arc::new(ticket_service),
    };
    Router::new()
        .route("/contacts/{contact_id}/notes", get(list_contact_notes))
        .with_state(state)
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
        // Configuration / lookup CRUD (PMS-321). GET handlers unchanged;
        // mutations are admin-gated inside each handler.
        .route("/statuses", get(get_statuses).post(create_status))
        .route("/statuses/{id}", put(update_status).delete(delete_status))
        .route("/priorities", get(get_priorities).post(create_priority))
        .route(
            "/priorities/{id}",
            put(update_priority).delete(delete_priority),
        )
        .route("/queues", get(get_queues).post(create_queue))
        .route("/queues/{id}", put(update_queue).delete(delete_queue))
        .route("/types", get(get_types).post(create_type))
        .route("/types/{id}", put(update_type).delete(delete_type))
        .route("/categories", get(get_categories).post(create_category))
        .route(
            "/categories/{id}",
            put(update_category).delete(delete_category),
        )
        .with_state(state)
}

async fn list_tickets(
    State(state): State<TicketRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Query(mut filter): Query<TicketFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketResponse>>> {
    // F9: validate filter inputs.
    filter.validate()?;
    // mokosh-contact-login prompt 008: contact-plane callers must hold
    // tickets:read AND get their listing scoped to their own Company so a
    // guessed `company_id` query param cannot widen visibility.
    let (tenant, caller_user_id) = match &caller {
        CallerContext::Staff(state) => {
            let user = state.user.as_ref().ok_or(AppError::Unauthorized)?;
            (user.tenant(), Some(user.id))
        }
        CallerContext::Contact(session) => {
            caller.require_capability(caps::TICKETS_READ, &db).await?;
            filter.company_id = Some(session.company_id);
            (caller.tenant(), None)
        }
    };
    let (responses, total) = state
        .ticket_service
        .list_ticket_responses(tenant, caller_user_id, &filter, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        responses,
        &pagination,
        total,
    )))
}

async fn create_ticket(
    State(state): State<TicketRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<CreateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;
    let resp = match &caller {
        CallerContext::Staff(auth) => {
            let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            let ticket = state
                .ticket_service
                .create_ticket(user.tenant(), user.id, &request, &ctx)
                .await?;
            state
                .ticket_service
                .get_ticket_response(user.tenant(), ticket.id)
                .await?
        }
        CallerContext::Contact(session) => {
            // mokosh-contact-login prompt 008: gate on the DB-loaded cap
            // set (JWT `caps` is UI-only). Force the ticket's
            // `company_id` and `contact_id` to the session's own so a
            // spoofed body cannot open a ticket against another
            // Company; stamp `source = "portal"` so downstream
            // reporting can attribute contact-originated volume.
            caller.require_capability(caps::TICKETS_WRITE, &db).await?;
            state
                .ticket_service
                .create_portal_ticket(
                    caller.tenant(),
                    session.company_id,
                    session.id,
                    request.title.clone(),
                    request.description.clone(),
                    request.priority_id,
                    request.type_id,
                )
                .await?
        }
    };
    Ok(Json(resp))
}

async fn get_ticket(
    State(state): State<TicketRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(ticket_id): Path<Uuid>,
) -> AppResult<Json<TicketResponse>> {
    // mokosh-contact-login prompt 008: contact-plane callers must hold
    // tickets:read AND own the ticket's Company; a foreign ticket
    // surfaces as 404 (not 403) so a probe cannot confirm existence.
    let tenant = caller.tenant();
    let resp = state
        .ticket_service
        .get_ticket_response(tenant, ticket_id)
        .await?;
    if let CallerContext::Contact(session) = &caller {
        caller.require_capability(caps::TICKETS_READ, &db).await?;
        if resp.company_id != session.company_id {
            return Err(AppError::NotFound("Ticket".to_string()));
        }
    }
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
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(ticket_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketNoteResponse>>> {
    // PMS-935: staff branch keeps the full note stream (public,
    // internal, resolution, time_entry) - agent back-channel
    // discussion belongs on the internal notes. Contact branch must
    // hold `tickets:read` AND own the parent ticket's Company; the
    // service scopes the query to `note_type = 'public'` so internal
    // notes never reach the wire.
    let tenant = caller.tenant();
    let (notes, total) = match &caller {
        CallerContext::Staff(auth) => {
            let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            state
                .ticket_service
                .get_ticket_notes(user.tenant(), ticket_id, &pagination)
                .await?
        }
        CallerContext::Contact(session) => {
            caller.require_capability(caps::TICKETS_READ, &db).await?;
            state
                .ticket_service
                .list_portal_ticket_notes(tenant, session.company_id, ticket_id, &pagination)
                .await?
        }
    };

    let responses: Vec<TicketNoteResponse> = notes
        .into_iter()
        .map(|n| TicketNoteResponse {
            id: n.id,
            note_type: n.note_type,
            content: n.content,
            is_email_sent: n.is_email_sent,
            created_by_id: n.created_by_id,
            created_by_name: n.created_by_name.unwrap_or_default(),
            created_by_contact_id: n.created_by_contact_id,
            created_at: n.created_at,
        })
        .collect();

    Ok(Json(PaginatedResponse::from_params(
        responses,
        &pagination,
        total,
    )))
}

/// PMS-468: agent UI "all comments from this contact" feed. Returns
/// every `note_type='public'` note authored by the contact (i.e.
/// `created_by_contact_id = $contact_id`) across the tenant's
/// tickets, paginated. Tenant-scoped so a contact in another tenant
/// cannot be queried by a guessed UUID; admin guard kept off since
/// every authenticated user already needs ticket-list access to
/// reach the contact detail page that calls this.
async fn list_contact_notes(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Path(contact_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketNoteResponse>>> {
    let (notes, total) = state
        .ticket_service
        .list_notes_by_contact(user.tenant(), contact_id, &pagination)
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
            created_by_contact_id: n.created_by_contact_id,
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
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    ctx: crate::modules::audit::AuditCtx,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<CreateNoteRequest>,
) -> AppResult<Json<TicketNoteResponse>> {
    request.validate()?;

    let (note, name_fallback) = match &caller {
        CallerContext::Staff(auth) => {
            let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            let note = state
                .ticket_service
                .add_note(user.tenant(), ticket_id, user.id, &request, &ctx)
                .await?;
            let fallback = user.full_name();
            (note, fallback)
        }
        CallerContext::Contact(session) => {
            // mokosh-contact-login prompt 008: gate on tickets:comment
            // AND refuse anything but `public` notes so a customer
            // cannot post an `internal` or `resolution` note against
            // agent back-channel discussion.
            caller
                .require_capability(caps::TICKETS_COMMENT, &db)
                .await?;
            if request.note_type != NoteType::Public {
                return Err(AppError::Forbidden(
                    "Contacts may only post public notes.".to_string(),
                ));
            }
            let note = state
                .ticket_service
                .create_portal_ticket_note(
                    caller.tenant(),
                    session.company_id,
                    session.id,
                    ticket_id,
                    request.content.clone(),
                )
                .await?;
            (note, session.email.clone())
        }
    };

    Ok(Json(TicketNoteResponse {
        id: note.id,
        note_type: note.note_type,
        content: note.content,
        is_email_sent: note.is_email_sent,
        created_by_id: note.created_by_id,
        created_by_name: note.created_by_name.unwrap_or(name_fallback),
        created_by_contact_id: note.created_by_contact_id,
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

// ----------------------------------------------------------------------------
// Lookup management (PMS-321). Mutations require admin (`RequireAdmin`),
// matching the asset-type write routes; reads stay on `RequireAuth`.
// ----------------------------------------------------------------------------

async fn create_status(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertTicketStatusRequest>,
) -> AppResult<Json<TicketStatus>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .create_status(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_status(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTicketStatusRequest>,
) -> AppResult<Json<TicketStatus>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .update_status(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_status(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state.ticket_service.delete_status(user.tenant(), id).await
}

async fn create_priority(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertTicketPriorityRequest>,
) -> AppResult<Json<TicketPriority>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .create_priority(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_priority(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTicketPriorityRequest>,
) -> AppResult<Json<TicketPriority>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .update_priority(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_priority(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state
        .ticket_service
        .delete_priority(user.tenant(), id)
        .await
}

async fn create_queue(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertTicketQueueRequest>,
) -> AppResult<Json<TicketQueue>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .create_queue(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_queue(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTicketQueueRequest>,
) -> AppResult<Json<TicketQueue>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .update_queue(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_queue(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state.ticket_service.delete_queue(user.tenant(), id).await
}

async fn create_type(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertTicketTypeRequest>,
) -> AppResult<Json<TicketType>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .create_type(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_type(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTicketTypeRequest>,
) -> AppResult<Json<TicketType>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .update_type(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_type(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state.ticket_service.delete_type(user.tenant(), id).await
}

async fn get_categories(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<TicketCategoryResponse>>> {
    let (categories, total) = state
        .ticket_service
        .get_categories(user.tenant(), &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        categories,
        &pagination,
        total,
    )))
}

async fn create_category(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    ctx: crate::modules::audit::AuditCtx,
    Json(request): Json<UpsertTicketCategoryRequest>,
) -> AppResult<Json<TicketCategoryResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .create_category(user.tenant(), &request, &ctx)
            .await?,
    ))
}

async fn update_category(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpsertTicketCategoryRequest>,
) -> AppResult<Json<TicketCategoryResponse>> {
    request.validate()?;
    Ok(Json(
        state
            .ticket_service
            .update_category(user.tenant(), id, &request)
            .await?,
    ))
}

async fn delete_category(
    State(state): State<TicketRouterState>,
    RequireAuth(user): RequireAuth,
    _a: RequireAdmin,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    state
        .ticket_service
        .delete_category(user.tenant(), id)
        .await
}
