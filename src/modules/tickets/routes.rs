//! Ticket API routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use super::{
    AttachmentService, CreateNoteRequest, CreateTicketRequest, NoteType, TicketCategoryResponse,
    TicketFilter, TicketNoteResponse, TicketPriority, TicketQueue, TicketResponse, TicketService,
    TicketStatus, TicketType, UpdateTicketRequest, UpsertTicketCategoryRequest,
    UpsertTicketPriorityRequest, UpsertTicketQueueRequest, UpsertTicketStatusRequest,
    UpsertTicketTypeRequest,
};
use crate::db::Database;
use crate::modules::approvals::{ApprovalResponse, ApprovalsService};
use crate::modules::auth::{
    CallerContext, RequireAdmin, RequireAuth, RequireCallerContext, TenantScoped,
};
use crate::modules::contact_portal::capabilities as caps;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct TicketRouterState {
    pub ticket_service: Arc<TicketService>,
    /// PMS-936: the portal attach-file endpoint needs the shared
    /// attachment blob pipeline. Optional so unit tests and helper
    /// routers (e.g. `contact_notes_routes`) can construct the state
    /// without wiring an attachment store.
    pub attachment_service: Option<Arc<AttachmentService>>,
    /// PMS-937: `POST /tickets/{id}/approvals/request` (contact-plane
    /// approval-request surface) delegates into the approvals
    /// service. Optional so helper routers that only expose the
    /// notes-feed surface (e.g. `contact_notes_routes`) can construct
    /// the state without wiring an approvals service.
    pub approvals_service: Option<Arc<ApprovalsService>>,
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
        attachment_service: None,
        approvals_service: None,
    };
    Router::new()
        .route("/contacts/{contact_id}/notes", get(list_contact_notes))
        .with_state(state)
}

/// Create the ticket router.
///
/// PMS-936 (foundation pass): also takes an `AttachmentService` so the
/// portal `POST /tickets/{id}/attachments` endpoint can reuse the
/// shared blob pipeline (same on-disk layout + sanitisation + size cap
/// as the per-note attachment surface). Kept behind an `Option` on the
/// router state so helper routers (e.g. `contact_notes_routes`) can
/// still construct a state without an attachment store.
///
/// PMS-937: also takes an `ApprovalsService` so
/// `POST /tickets/{id}/approvals/request` (contact-plane
/// approval-request surface) can delegate into the shared approvals
/// service without duplicating the row-insert SQL.
pub fn ticket_routes(
    ticket_service: TicketService,
    attachment_service: AttachmentService,
    approvals_service: ApprovalsService,
) -> Router {
    let state = TicketRouterState {
        ticket_service: Arc::new(ticket_service),
        attachment_service: Some(Arc::new(attachment_service)),
        approvals_service: Some(Arc::new(approvals_service)),
    };

    Router::new()
        // Tickets
        .route("/", get(list_tickets))
        .route("/", post(create_ticket))
        .route("/{ticket_id}", get(get_ticket))
        .route("/{ticket_id}", put(update_ticket))
        // PMS-937: dual-plane PATCH. Contact callers gate on
        // `tickets:edit_own` and may only edit the title / description
        // of a ticket they themselves opened; every other field is
        // silently stripped from the body. Staff callers accept every
        // editable field (delegates to the same underlying
        // `update_ticket` service the PUT route uses).
        .route("/{ticket_id}", patch(patch_ticket))
        .route("/{ticket_id}", delete(delete_ticket))
        .route("/{ticket_id}/assign", post(assign_ticket))
        // PMS-937: contact-initiated approval-request surface. Gated
        // on `tickets:request_approval` for the contact plane; staff
        // callers reuse the existing approvals service through the
        // same handler so the endpoint is a single URL for both
        // planes.
        .route(
            "/{ticket_id}/approvals/request",
            post(request_approval_on_ticket),
        )
        // PMS-936: portal contact reopens a closed ticket (gated on
        // `tickets:reopen`) via the shared `reopen_portal_ticket`
        // service path. Staff callers also reach it and bypass the cap
        // gate; a foreign-Company ticket surfaces as 404.
        .route("/{ticket_id}/reopen", post(reopen_ticket))
        // PMS-936: portal contact attaches a file to a ticket
        // (gated on `tickets:attach_file`) via the shared attachments
        // blob pipeline. JSON body carries base64 bytes so we skip the
        // multipart parsing rathole; row is stamped with
        // `created_by_contact_id`.
        .route("/{ticket_id}/attachments", post(portal_attach_file))
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

/// PMS-937: PATCH body for the contact-owned ticket-edit surface.
/// The full staff-plane editable set lives on
/// [`UpdateTicketRequest`], which is what the PATCH handler
/// deserialises for the staff branch. Contact callers hit the same
/// endpoint and body shape, but only `title` and `description` are
/// honoured (every other field the JSON might carry is silently
/// stripped so the same body works for both planes without a
/// separate contact-only route).
async fn patch_ticket(
    State(state): State<TicketRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    ctx: crate::modules::audit::AuditCtx,
    Path(ticket_id): Path<Uuid>,
    Json(request): Json<UpdateTicketRequest>,
) -> AppResult<Json<TicketResponse>> {
    request.validate()?;
    let tenant = caller.tenant();
    match &caller {
        CallerContext::Staff(auth) => {
            let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            state
                .ticket_service
                .update_ticket(user.tenant(), ticket_id, user.id, &request, &ctx)
                .await?;
        }
        CallerContext::Contact(session) => {
            // Cap gate first so a contact without `tickets:edit_own`
            // cannot learn whether the ticket exists.
            caller
                .require_capability(caps::TICKETS_EDIT_OWN, &db)
                .await?;

            // Load the row to check Company scope + reporter-contact
            // ownership. Same 404-leak-free posture as `get_ticket`:
            // a foreign Company OR a same-Company-but-different-contact
            // ticket both surface as 404 so the contact plane never
            // discloses which case they hit.
            let ticket = state.ticket_service.get_ticket(tenant, ticket_id).await?;
            if ticket.company_id != session.company_id {
                return Err(AppError::NotFound("Ticket".to_string()));
            }
            if ticket.contact_id != Some(session.id) {
                return Err(AppError::NotFound("Ticket".to_string()));
            }

            // Strip every field but title / description. Rebuild a
            // fresh UpdateTicketRequest so a spoofed `status_id`,
            // `priority_id`, `assignee_id`, `company_id`, etc. cannot
            // reach the service layer. Reject an all-empty PATCH
            // (nothing to update) as a 400 so the contact does not
            // silently hit the audit-only path.
            if request.title.is_none() && request.description.is_none() {
                return Err(AppError::BadRequest(
                    "PATCH body must set at least one of title, description".to_string(),
                ));
            }
            let stripped = UpdateTicketRequest {
                title: request.title,
                description: request.description,
                status_id: None,
                priority_id: None,
                type_id: None,
                category_id: None,
                queue_id: None,
                contact_id: None,
                site_id: None,
                assigned_to_id: None,
                team_id: None,
                contract_id: None,
                sla_id: None,
                scheduled_start: None,
                scheduled_end: None,
                estimated_hours: None,
                is_billable: None,
                billing_status: None,
                asset_id: None,
                custom_fields: None,
                tags: None,
            };
            // Attribute the mutation to the tenant's first
            // admin/manager user for `last_updated_by_id`; the portal
            // flow has no `users` identity of its own. Same fallback
            // shape `create_portal_ticket` uses.
            state
                .ticket_service
                .update_portal_ticket(tenant, session.company_id, session.id, ticket_id, stripped)
                .await?;
        }
    }
    let resp = state
        .ticket_service
        .get_ticket_response(tenant, ticket_id)
        .await?;
    Ok(Json(resp))
}

/// PMS-937: body for `POST /tickets/{id}/approvals/request`.
/// Contact plane accepts `{ note }`; staff plane uses the same body
/// so the SPA can drive both planes through one call.
#[derive(serde::Deserialize, validator::Validate)]
struct RequestApprovalBody {
    #[validate(length(min = 1, max = 2000))]
    note: String,
}

/// PMS-937: contact-initiated approval-request surface. Contact
/// callers gate on `tickets:request_approval` and Company-scope; the
/// approver defaults to the tenant's `admin` role so any MSP admin
/// can decide. Staff callers reuse the existing phase-1 approvals
/// flow so the endpoint is backwards-compatible - staff who need to
/// target a specific approver keep using `POST /tickets/{id}/approvals`
/// with the full `CreateApprovalRequest` body.
async fn request_approval_on_ticket(
    State(state): State<TicketRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(ticket_id): Path<Uuid>,
    Json(body): Json<RequestApprovalBody>,
) -> AppResult<Json<ApprovalResponse>> {
    body.validate()?;
    let approvals = state
        .approvals_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("Approvals service not configured".to_string()))?;
    let tenant = caller.tenant();
    let tenant_uuid = tenant.get();
    let resp = match &caller {
        CallerContext::Staff(auth) => {
            let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            approvals
                .create_staff_request(tenant_uuid, ticket_id, user.id, body.note)
                .await?
        }
        CallerContext::Contact(session) => {
            caller
                .require_capability(caps::TICKETS_REQUEST_APPROVAL, &db)
                .await?;
            // Company-scope + existence check via the ticket service so
            // a foreign-Company ticket surfaces as 404 before we insert.
            state
                .ticket_service
                .assert_ticket_visible_to_company(tenant, ticket_id, session.company_id)
                .await?;
            approvals
                .create_contact_request(tenant_uuid, ticket_id, session.id, body.note)
                .await?
        }
    };
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

/// PMS-936: body for `POST /tickets/{id}/reopen`. Optional reason is
/// folded into the public audit note the service appends so the agent
/// sees WHY the ticket came back.
#[derive(serde::Deserialize, Default)]
struct ReopenBody {
    #[serde(default)]
    reason: Option<String>,
}

/// PMS-936: reopen a ticket. Contact-plane callers gate on
/// `tickets:reopen` and get the Company-scope check via the service's
/// `assert_portal_ticket_visible`; staff callers bypass the cap gate
/// and reopen through the same shared code path.
async fn reopen_ticket(
    State(state): State<TicketRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(ticket_id): Path<Uuid>,
    body: Option<Json<ReopenBody>>,
) -> AppResult<Json<TicketResponse>> {
    let tenant = caller.tenant();
    let reason = body.and_then(|Json(b)| b.reason);
    let resp = match &caller {
        CallerContext::Staff(auth) => {
            auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            // Staff reopen shares the portal reopen implementation so
            // the audit-note posture is identical. Look up the ticket's
            // own company_id first so the Company-scope check inside
            // `reopen_portal_ticket` still succeeds (staff are
            // unbounded, so any company is acceptable). `contact_id =
            // None` leaves the audit note's `created_by_contact_id`
            // NULL; the note's authorship stamps the fallback
            // staff-admin id the service's audit-note path resolves.
            let existing = state
                .ticket_service
                .get_ticket_response(tenant, ticket_id)
                .await?;
            state
                .ticket_service
                .reopen_portal_ticket(
                    tenant,
                    existing.company_id,
                    None,
                    ticket_id,
                    reason.as_deref(),
                )
                .await?
        }
        CallerContext::Contact(session) => {
            caller.require_capability(caps::TICKETS_REOPEN, &db).await?;
            state
                .ticket_service
                .reopen_portal_ticket(
                    tenant,
                    session.company_id,
                    Some(session.id),
                    ticket_id,
                    reason.as_deref(),
                )
                .await?
        }
    };
    Ok(Json(resp))
}

/// PMS-936: JSON body for `POST /tickets/{id}/attachments`. Base64
/// bytes keep the wire format simple (no multipart parsing needed for
/// the portal-side upload; the shared blob pipeline enforces the same
/// size cap and stores the row identically).
#[derive(serde::Deserialize)]
struct PortalAttachBody {
    filename: String,
    #[serde(default)]
    content_type: Option<String>,
    data_base64: String,
}

/// PMS-936: attach a file to a ticket via the portal contact plane.
/// Uses the shared `AttachmentService` blob pipeline so the row lands
/// alongside inbound-email + agent uploads and the on-disk layout is
/// identical; `created_by_contact_id` attribution flags it as
/// contact-uploaded so the agent UI can render it distinctly.
async fn portal_attach_file(
    State(state): State<TicketRouterState>,
    RequireCallerContext(caller): RequireCallerContext,
    axum::extract::Extension(db): axum::extract::Extension<Database>,
    Path(ticket_id): Path<Uuid>,
    Json(body): Json<PortalAttachBody>,
) -> AppResult<Json<super::AttachmentResponse>> {
    let attachment_service = state
        .attachment_service
        .as_ref()
        .ok_or_else(|| AppError::Configuration("Attachment service not configured".to_string()))?;
    let tenant = caller.tenant();
    let tenant_uuid = tenant.get();

    // Cap gate first: a contact without `tickets:attach_file` must not
    // learn whether the ticket exists.
    let (uploaded_by_id, created_by_contact_id) = match &caller {
        CallerContext::Staff(auth) => {
            let user = auth.user.as_ref().ok_or(AppError::Unauthorized)?;
            (Some(user.id), None)
        }
        CallerContext::Contact(session) => {
            caller
                .require_capability(caps::TICKETS_ATTACH_FILE, &db)
                .await?;
            // Verify the ticket lives on the caller's Company; leak-free
            // 404 on a foreign ticket.
            attachment_service
                .assert_ticket_visible_to_company(tenant_uuid, ticket_id, session.company_id)
                .await?;
            (None, Some(session.id))
        }
    };

    // Decode the base64 payload. Reject an empty body up front so the
    // shared pipeline's size cap never sees zero bytes.
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.data_base64.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("data_base64 decode: {e}")))?;
    if bytes.is_empty() {
        return Err(AppError::BadRequest(
            "data_base64 decoded to zero bytes".to_string(),
        ));
    }
    let mime = body
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let resp = attachment_service
        .store_ticket_level_attachment(
            tenant_uuid,
            ticket_id,
            uploaded_by_id,
            created_by_contact_id,
            body.filename,
            mime,
            bytes,
        )
        .await?;
    Ok(Json(resp))
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
