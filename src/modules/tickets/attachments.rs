//! PMS-483: ticket-note attachment upload / download / delete.
//!
//! Storage: local disk under the configured `ATTACHMENT_DIR` (default
//! `./attachments`). Each blob lives at `{dir}/{tenant_id}/{attachment_id}`;
//! the on-disk name is just the attachment uuid so a hostile
//! `file_name` cannot escape the per-tenant directory or shadow a
//! sibling tenant's blob. The original filename is stored verbatim in
//! the DB row and only used to set the `Content-Disposition` header on
//! download.
//!
//! Authorisation:
//!   - Agent uploads attribute via `uploaded_by_id` (a `users` row),
//!     leaving `created_by_contact_id` NULL.
//!   - Portal uploads attribute via `created_by_contact_id` (a
//!     `contacts` row), leaving `uploaded_by_id` NULL. The portal
//!     handlers double-check the ticket's `company_id` equals the
//!     authenticated contact's `company_id` so a contact cannot
//!     attach to a sibling-company ticket whose UUID they guessed.
//!   - Download is symmetric: an agent sees every attachment in their
//!     tenant; a portal contact sees only their own company's.
//!
//! Size cap: `ATTACHMENT_MAX_BYTES` (default 25 MiB) enforced
//! server-side before the bytes are written to disk; oversize uploads
//! return 413.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::{RequireAuth, TenantId, TenantScoped};
use crate::utils::error::{AppError, AppResult};

/// Default size cap when `ATTACHMENT_MAX_BYTES` is unset. 25 MiB
/// matches what the ticket spec cites as the v1 default.
const DEFAULT_MAX_BYTES: u64 = 25 * 1024 * 1024;
/// Default storage directory when `ATTACHMENT_DIR` is unset. Resolves
/// relative to the server's CWD; production should set the env to an
/// absolute path on a mounted volume.
const DEFAULT_DIR: &str = "./attachments";

#[derive(Clone, Debug)]
pub struct AttachmentConfig {
    pub dir: PathBuf,
    pub max_bytes: u64,
}

impl AttachmentConfig {
    pub fn from_env() -> Self {
        let dir = std::env::var("ATTACHMENT_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR));
        let max_bytes = std::env::var("ATTACHMENT_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_BYTES);
        Self { dir, max_bytes }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentResponse {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub note_id: Option<Uuid>,
    pub file_name: String,
    pub file_size: i32,
    pub mime_type: String,
    pub uploaded_by_id: Option<Uuid>,
    pub created_by_contact_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct AttachmentRow {
    id: Uuid,
    ticket_id: Uuid,
    note_id: Option<Uuid>,
    file_name: String,
    file_size: i32,
    mime_type: String,
    storage_path: String,
    uploaded_by_id: Option<Uuid>,
    created_by_contact_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

impl From<AttachmentRow> for AttachmentResponse {
    fn from(r: AttachmentRow) -> Self {
        Self {
            id: r.id,
            ticket_id: r.ticket_id,
            note_id: r.note_id,
            file_name: r.file_name,
            file_size: r.file_size,
            mime_type: r.mime_type,
            uploaded_by_id: r.uploaded_by_id,
            created_by_contact_id: r.created_by_contact_id,
            created_at: r.created_at,
        }
    }
}

#[derive(Clone)]
pub struct AttachmentService {
    db: Database,
    config: AttachmentConfig,
}

impl AttachmentService {
    pub fn new(db: Database, config: AttachmentConfig) -> Self {
        Self { db, config }
    }

    fn storage_path_for(&self, tenant_id: Uuid, attachment_id: Uuid) -> PathBuf {
        self.config
            .dir
            .join(tenant_id.to_string())
            .join(attachment_id.to_string())
    }

    /// Verify the note belongs to the ticket and the ticket belongs to
    /// the tenant. Returns NotFound when the (tenant, ticket, note)
    /// triple does not resolve, so a guessed uuid never leaks across
    /// tenant boundaries.
    async fn assert_note_in_ticket(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        note_id: Uuid,
    ) -> AppResult<()> {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT n.id FROM ticket_notes n \
             JOIN tickets t ON t.id = n.ticket_id \
             WHERE n.id = $1 AND n.ticket_id = $2 AND t.tenant_id = $3",
        )
        .bind(note_id)
        .bind(ticket_id)
        .bind(tenant_id)
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound(
                "ticket note not found in tenant scope".into(),
            ));
        }
        Ok(())
    }

    /// Verify the ticket exists in the tenant; for portal callers,
    /// also require the ticket's company matches the contact's
    /// company. Returns NotFound on any mismatch.
    ///
    /// PMS-936: made `pub` so the dual-plane portal attach-file route
    /// (which lives on the tickets router, not this attachments
    /// router) can reuse the same leak-free scope check.
    pub async fn assert_ticket_visible_to_company(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        company_id: Uuid,
    ) -> AppResult<()> {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM tickets \
             WHERE id = $1 AND tenant_id = $2 AND company_id = $3",
        )
        .bind(ticket_id)
        .bind(tenant_id)
        .bind(company_id)
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound("ticket not visible".into()));
        }
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        note_id: Uuid,
    ) -> AppResult<Vec<AttachmentResponse>> {
        let rows: Vec<AttachmentRow> = sqlx::query_as(
            "SELECT id, ticket_id, note_id, file_name, file_size, mime_type, \
                    storage_path, uploaded_by_id, created_by_contact_id, created_at \
             FROM ticket_attachments \
             WHERE tenant_id = $1 AND ticket_id = $2 AND note_id = $3 \
             ORDER BY created_at ASC",
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(note_id)
        .fetch_all(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        note_id: Uuid,
        file_name: String,
        mime_type: String,
        bytes: Vec<u8>,
        uploader: Uploader,
    ) -> AppResult<AttachmentResponse> {
        let (uploaded_by_id, created_by_contact_id) = uploader.row_columns();
        self.insert_blob(
            tenant_id,
            ticket_id,
            Some(note_id),
            file_name,
            mime_type,
            bytes,
            uploaded_by_id,
            created_by_contact_id,
        )
        .await
    }

    /// PMS-450 AC3: persist an inbound email attachment. Unlike the
    /// agent / portal upload paths this allows a NULL `note_id` (an
    /// attachment on a freshly-created email ticket hangs off the
    /// ticket, not a note) and attributes authorship to the sender
    /// contact via `created_by_contact_id`. Reuses the same on-disk
    /// blob layout, sanitisation, and size cap as the interactive
    /// uploads so the download / delete surface treats the row
    /// identically.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_email_attachment(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        note_id: Option<Uuid>,
        contact_id: Uuid,
        file_name: String,
        mime_type: String,
        bytes: Vec<u8>,
    ) -> AppResult<AttachmentResponse> {
        self.insert_blob(
            tenant_id,
            ticket_id,
            note_id,
            file_name,
            mime_type,
            bytes,
            None,
            Some(contact_id),
        )
        .await
    }

    /// PMS-936: persist a ticket-level attachment uploaded via the
    /// portal contact plane (or staff, when the same endpoint is
    /// reached with a staff bearer). Takes an `Option<Uuid>` for each
    /// of the two attribution columns so the caller can stamp
    /// exactly one and leave the other NULL. Reuses the same on-disk
    /// layout + size cap as the agent / email paths.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_ticket_level_attachment(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        uploaded_by_id: Option<Uuid>,
        created_by_contact_id: Option<Uuid>,
        file_name: String,
        mime_type: String,
        bytes: Vec<u8>,
    ) -> AppResult<AttachmentResponse> {
        self.insert_blob(
            tenant_id,
            ticket_id,
            None,
            file_name,
            mime_type,
            bytes,
            uploaded_by_id,
            created_by_contact_id,
        )
        .await
    }

    /// Shared blob path for every attachment origin: enforce the size
    /// cap, write the bytes to `{dir}/{tenant}/{uuid}`, then insert the
    /// metadata row. The two authorship columns are passed through
    /// verbatim so each caller sets the column that matches its origin
    /// (agent -> `uploaded_by_id`, portal / email -> `created_by_contact_id`).
    #[allow(clippy::too_many_arguments)]
    async fn insert_blob(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        note_id: Option<Uuid>,
        file_name: String,
        mime_type: String,
        bytes: Vec<u8>,
        uploaded_by_id: Option<Uuid>,
        created_by_contact_id: Option<Uuid>,
    ) -> AppResult<AttachmentResponse> {
        let size = bytes.len();
        if size as u64 > self.config.max_bytes {
            return Err(AppError::PayloadTooLarge(format!(
                "attachment exceeds {} byte cap",
                self.config.max_bytes
            )));
        }
        let id = Uuid::new_v4();
        let path = self.storage_path_for(tenant_id, id);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| AppError::Internal(format!("could not create attachment dir: {e}")))?;
        }
        tokio::fs::write(&path, &bytes)
            .await
            .map_err(|e| AppError::Internal(format!("could not write attachment: {e}")))?;
        let storage_path = path.to_string_lossy().to_string();

        let safe_name = sanitize_filename(&file_name);
        let safe_mime = sanitize_mime_type(&mime_type);

        // PMS-692: `ticket_attachments` is RLS-covered; the INSERT's WITH CHECK
        // compares `tenant_id` to the `app.current_tenant` GUC, so it must run in
        // a `begin_with_tenant` transaction. On the NOBYPASSRLS serving
        // connection an unset GUC rejects the write outright.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: AttachmentRow = sqlx::query_as(
            "INSERT INTO ticket_attachments \
                (id, tenant_id, ticket_id, note_id, file_name, file_size, \
                 mime_type, storage_path, uploaded_by_id, created_by_contact_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             RETURNING id, ticket_id, note_id, file_name, file_size, mime_type, \
                       storage_path, uploaded_by_id, created_by_contact_id, created_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(ticket_id)
        .bind(note_id)
        .bind(&safe_name)
        .bind(size as i32)
        .bind(&safe_mime)
        .bind(&storage_path)
        .bind(uploaded_by_id)
        .bind(created_by_contact_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.into())
    }

    async fn get(
        &self,
        tenant_id: Uuid,
        attachment_id: Uuid,
    ) -> AppResult<(AttachmentRow, Vec<u8>)> {
        let row: AttachmentRow = sqlx::query_as(
            "SELECT id, ticket_id, note_id, file_name, file_size, mime_type, \
                    storage_path, uploaded_by_id, created_by_contact_id, created_at \
             FROM ticket_attachments \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(attachment_id)
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?
        .ok_or_else(|| AppError::NotFound("attachment not found".into()))?;
        let bytes = tokio::fs::read(&row.storage_path)
            .await
            .map_err(|e| AppError::Internal(format!("attachment blob missing: {e}")))?;
        Ok((row, bytes))
    }

    async fn delete_one(&self, tenant_id: Uuid, attachment_id: Uuid) -> AppResult<()> {
        // PMS-692: RLS-covered write - run under the tenant GUC so the DELETE's
        // USING/WITH CHECK matches, then commit.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String,)> = sqlx::query_as(
            "DELETE FROM ticket_attachments \
             WHERE tenant_id = $1 AND id = $2 \
             RETURNING storage_path",
        )
        .bind(tenant_id)
        .bind(attachment_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let Some((path,)) = row else {
            return Err(AppError::NotFound("attachment not found".into()));
        };
        // Best-effort blob removal: a missing file is not a hard
        // error since the DB row is already gone (mirrors the soft-
        // delete posture of other modules).
        let _ = tokio::fs::remove_file(&path).await;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum Uploader {
    Agent { user_id: Uuid },
    Portal { contact_id: Uuid },
}

impl Uploader {
    fn row_columns(self) -> (Option<Uuid>, Option<Uuid>) {
        match self {
            Self::Agent { user_id } => (Some(user_id), None),
            Self::Portal { contact_id } => (None, Some(contact_id)),
        }
    }
}

/// Strip path separators, trim to 255 chars, fall back to "file" if
/// the result is empty. Only the on-disk name uses the uuid; this is
/// the value that ships in the `Content-Disposition` header.
fn sanitize_filename(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | '\0'))
        .take(255)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

fn sanitize_mime_type(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(100).collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "application/octet-stream".to_string()
    } else {
        trimmed.to_string()
    }
}

async fn read_multipart_file(mut multipart: Multipart) -> AppResult<(String, String, Vec<u8>)> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart parse: {e}")))?
    {
        let field_name = field.name().map(str::to_string).unwrap_or_default();
        if field_name != "file" {
            continue;
        }
        let file_name = field
            .file_name()
            .map(str::to_string)
            .unwrap_or_else(|| "file".to_string());
        let mime_type = field
            .content_type()
            .map(str::to_string)
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let bytes = field
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(format!("multipart read: {e}")))?;
        return Ok((file_name, mime_type, bytes.to_vec()));
    }
    Err(AppError::BadRequest(
        "missing 'file' part in multipart body".into(),
    ))
}

#[derive(Clone)]
pub struct AttachmentsRouterState {
    pub service: Arc<AttachmentService>,
}

pub fn agent_attachment_routes(service: AttachmentService) -> Router {
    let state = AttachmentsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route(
            "/tickets/{ticket_id}/notes/{note_id}/attachments",
            get(list_agent).post(upload_agent),
        )
        .route(
            "/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}",
            get(download_agent).delete(delete_agent),
        )
        .with_state(state)
}

async fn list_agent(
    State(s): State<AttachmentsRouterState>,
    RequireAuth(user): RequireAuth,
    Path((ticket_id, note_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<Vec<AttachmentResponse>>> {
    let tenant: TenantId = user.tenant();
    s.service
        .assert_note_in_ticket(tenant.get(), ticket_id, note_id)
        .await?;
    let rows = s.service.list(tenant.get(), ticket_id, note_id).await?;
    Ok(Json(rows))
}

async fn upload_agent(
    State(s): State<AttachmentsRouterState>,
    RequireAuth(user): RequireAuth,
    Path((ticket_id, note_id)): Path<(Uuid, Uuid)>,
    multipart: Multipart,
) -> AppResult<Json<AttachmentResponse>> {
    let tenant_uuid = user.tenant().get();
    s.service
        .assert_note_in_ticket(tenant_uuid, ticket_id, note_id)
        .await?;
    let (file_name, mime_type, bytes) = read_multipart_file(multipart).await?;
    let resp = s
        .service
        .create(
            tenant_uuid,
            ticket_id,
            note_id,
            file_name,
            mime_type,
            bytes,
            Uploader::Agent { user_id: user.id },
        )
        .await?;
    Ok(Json(resp))
}

async fn download_agent(
    State(s): State<AttachmentsRouterState>,
    RequireAuth(user): RequireAuth,
    Path((ticket_id, note_id, attachment_id)): Path<(Uuid, Uuid, Uuid)>,
) -> AppResult<Response> {
    let tenant_uuid = user.tenant().get();
    s.service
        .assert_note_in_ticket(tenant_uuid, ticket_id, note_id)
        .await?;
    let (row, bytes) = s.service.get(tenant_uuid, attachment_id).await?;
    if row.ticket_id != ticket_id || row.note_id != Some(note_id) {
        return Err(AppError::NotFound("attachment not on this note".into()));
    }
    Ok(attachment_response(row, bytes))
}

async fn delete_agent(
    State(s): State<AttachmentsRouterState>,
    RequireAuth(user): RequireAuth,
    Path((ticket_id, note_id, attachment_id)): Path<(Uuid, Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    let tenant_uuid = user.tenant().get();
    s.service
        .assert_note_in_ticket(tenant_uuid, ticket_id, note_id)
        .await?;
    s.service.delete_one(tenant_uuid, attachment_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn attachment_response(row: AttachmentRow, bytes: Vec<u8>) -> Response {
    let disposition = format!(
        "attachment; filename=\"{}\"",
        row.file_name.replace('"', "")
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, row.mime_type),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        Body::from(bytes),
    )
        .into_response()
}
