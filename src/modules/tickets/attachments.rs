//! PMS-483: ticket-note attachment upload / download / delete.
//!
//! Storage: PMS-910 moved that decision to `crate::storage`, which owns the
//! root and the layout for every kind of stored object. A blob is addressed by
//! `(tenant_id, attachment_id)` and this module never builds a path; the
//! on-disk name is still just the attachment uuid so a hostile
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
//!
//! ## Inline images (PMS-941)
//!
//! A ticket description or note is markdown, so an author can embed an image in
//! it. The browser then fetches that image as `<img src="...">`, which carries
//! no `Authorization` header, and the SPA holds a bearer rather than a cookie:
//! there is no authenticated form of that request to make. So the bytes come
//! back from `GET /api/v1/public/tickets/attachments/{id}`, with no session, no
//! cookie and no signature, exactly as PMS-923 does for KB article images. The
//! attachment's v4 UUID is the credential.
//!
//! That read serves ONLY rows with `is_inline` set, and only
//! [`AttachmentService::create_inline`] sets it. Everything else in this table
//! stays behind the authenticated, company-scoped download routes below,
//! because it was stored under that contract: a portal upload from a customer,
//! or an attachment on the inbound email that opened the ticket (PMS-450). The
//! table has no MIME allowlist and a 25 MiB cap, so "serve any attachment by
//! id" would have made an invoice or a log bundle world-readable to anyone
//! holding a UUID. Inline uploads are image-only (`utils::inline_image`, which
//! refuses SVG) and capped far lower.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::{RequireAuth, TenantId, TenantScoped};
// mokosh-contact-login: the /portal/* customer-portal surface retired on this
// branch, so `crate::modules::portal::*` is gone with it. Portal-plane
// attachment uploads are folded into the contact plane in a later prompt.
use crate::storage::{FileLedger, FileRecord, LocalStore, ObjectKey, ObjectStore};
use crate::utils::error::{AppError, AppResult};
use crate::utils::inline_image::check_inline_image_mime;

/// Default size cap when `ATTACHMENT_MAX_BYTES` is unset. 25 MiB
/// matches what the ticket spec cites as the v1 default.
const DEFAULT_MAX_BYTES: u64 = 25 * 1024 * 1024;
/// PMS-783: an attachment blob is addressed by a v4 uuid and is never rewritten
/// in place (a replacement is a new row under a new uuid, and `delete_one`
/// removes it), so the bytes behind one URL are immutable and a year is safe.
/// `private` because both download routes are authenticated and company-scoped:
/// no shared cache may keep a copy. Revise the `immutable` half if in-place
/// replacement is ever added.
const CACHE_CONTROL_VALUE: &str = "private, max-age=31536000, immutable";
/// PMS-941: the inline-image read is unauthenticated, so `public` rather than
/// `private` - a shared cache in front of the API may keep a copy, which is the
/// point of a route a browser hits once per rendered page. Immutability is the
/// same property the private value relies on: the uuid names one set of bytes
/// for its whole life.
const INLINE_CACHE_CONTROL_VALUE: &str = "public, max-age=31536000, immutable";
/// PMS-941: cap for an image embedded in a description or note, matching the KB
/// article image. Deliberately not `ATTACHMENT_MAX_BYTES`: 25 MiB is a size for
/// a file somebody chose to download, whereas this one is fetched by every
/// browser that renders the ticket, and it is served without a session. Taken
/// as a floor against the configured cap rather than a replacement, so an
/// operator who lowers `ATTACHMENT_MAX_BYTES` lowers this too, while raising it
/// does not raise this.
const INLINE_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// The byte cap an inline image is held to, given the configured attachment
/// cap. A floor rather than a replacement: lowering `ATTACHMENT_MAX_BYTES`
/// lowers this too, raising it does not raise this.
fn inline_cap(configured_max_bytes: u64) -> u64 {
    configured_max_bytes.min(INLINE_MAX_BYTES)
}

/// The path a client points an `<img>` at. Relative on purpose: the SPA joins
/// it with the API base it already knows, and nothing here can know that base.
pub fn inline_attachment_path(id: Uuid) -> String {
    format!("/api/v1/public/tickets/attachments/{id}")
}

#[derive(Clone, Debug)]
pub struct AttachmentConfig {
    pub max_bytes: u64,
}

impl AttachmentConfig {
    pub fn from_env() -> Self {
        let max_bytes = std::env::var("ATTACHMENT_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_BYTES);
        Self { max_bytes }
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
    /// PMS-941: true only for a row the inline-image upload path created, which
    /// is the same set of rows the public read will serve.
    pub is_inline: bool,
    /// Where to point an `<img>`, or `None`. `None` for every attachment that
    /// is not inline, because there is no public URL for those and advertising
    /// one would be a promise this server does not keep: the public route 404s
    /// on a row without the flag.
    pub url: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AttachmentRow {
    id: Uuid,
    ticket_id: Uuid,
    note_id: Option<Uuid>,
    file_name: String,
    file_size: i32,
    mime_type: String,
    /// PMS-910: still written, because the column is `NOT NULL` and every
    /// existing row holds one, but no longer READ: a blob is opened through the
    /// store from `(tenant_id, id)` instead, so a path in this row cannot send
    /// a read anywhere the store would not.
    #[allow(dead_code)]
    storage_path: String,
    tenant_id: Uuid,
    uploaded_by_id: Option<Uuid>,
    created_by_contact_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    is_inline: bool,
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
            is_inline: r.is_inline,
            url: r.is_inline.then(|| inline_attachment_path(r.id)),
        }
    }
}

#[derive(Clone)]
pub struct AttachmentService {
    db: Database,
    config: AttachmentConfig,
    /// PMS-910: where the bytes go. This module no longer knows.
    pub(crate) store: LocalStore,
    /// PMS-957: one row per stored file, so the tenant rollup is a fact.
    ledger: FileLedger,
}

impl AttachmentService {
    pub fn new(db: Database, config: AttachmentConfig) -> Self {
        Self {
            ledger: FileLedger::new(db.clone()),
            db,
            config,
            store: LocalStore::from_env(),
        }
    }

    /// PMS-910: the layout lives in `crate::storage` now. This still resolves a
    /// path because `ticket_attachments.storage_path` is `NOT NULL` and every
    /// existing row holds one; the value it produces is byte-identical to what
    /// this method built before.
    fn storage_path_for(&self, tenant_id: Uuid, attachment_id: Uuid) -> AppResult<PathBuf> {
        self.store
            .path_for(&ObjectKey::ticket_attachment(tenant_id, attachment_id))
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

    /// PMS-941: verify the ticket exists in the tenant, with no note and no
    /// company in the question. An inline image hangs off the ticket, because
    /// it is embedded while the description or the note is still being written
    /// and there may be no note row yet to hang it from.
    async fn assert_ticket_in_tenant(&self, tenant_id: Uuid, ticket_id: Uuid) -> AppResult<()> {
        let exists: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM tickets WHERE id = $1 AND tenant_id = $2")
                .bind(ticket_id)
                .bind(tenant_id)
                .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
                .await?;
        if exists.is_none() {
            return Err(AppError::NotFound(
                "ticket not found in tenant scope".into(),
            ));
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
                    storage_path, tenant_id, uploaded_by_id, created_by_contact_id, created_at, \
                    is_inline \
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
            // An agent or portal note attachment is a file to download, not an
            // image to render, so it stays behind the authenticated routes.
            false,
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
            // PMS-450 attachments arrive from an inbound email and were never
            // offered a public URL; see the module header.
            false,
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
            false,
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
        is_inline: bool,
    ) -> AppResult<AttachmentResponse> {
        let size = bytes.len();
        if size as u64 > self.config.max_bytes {
            return Err(AppError::PayloadTooLarge(format!(
                "attachment exceeds {} byte cap",
                self.config.max_bytes
            )));
        }
        let id = Uuid::new_v4();
        let key = ObjectKey::ticket_attachment(tenant_id, id);
        self.store.put(&key, &bytes).await?;
        let storage_path = self
            .storage_path_for(tenant_id, id)?
            .to_string_lossy()
            .to_string();

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
                 mime_type, storage_path, uploaded_by_id, created_by_contact_id, \
                 is_inline) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             RETURNING id, ticket_id, note_id, file_name, file_size, mime_type, \
                       storage_path, tenant_id, uploaded_by_id, created_by_contact_id, created_at, \
                       is_inline",
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
        .bind(is_inline)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        // PMS-957: after the feature row, and under the same id, so the ledger
        // row and the attachment are one object rather than two that can
        // disagree. `uploaded_by_id` is None for a portal upload (the actor is
        // a `contacts` row) and for inbound email (there is no actor), which is
        // why migration 126 drops that column's NOT NULL.
        self.ledger
            .record(
                tenant_id,
                &key,
                id,
                FileRecord {
                    original_name: &safe_name,
                    mime_type: &safe_mime,
                    file_size: size as i64,
                    uploaded_by_id,
                    entity_type: "ticket_attachment",
                    entity_id: Some(id),
                },
            )
            .await?;
        Ok(row.into())
    }

    /// Metadata only: the row, never the blob.
    ///
    /// PMS-783: this used to be a `get` that also read the file into a `Vec`,
    /// which made every caller pay up to `ATTACHMENT_MAX_BYTES` of heap even
    /// when it only wanted one column (the portal delete's ownership check
    /// reads `created_by_contact_id` and nothing else). The download handlers
    /// now stream the blob straight off disk in `attachment_response`.
    async fn get_row(&self, tenant_id: Uuid, attachment_id: Uuid) -> AppResult<AttachmentRow> {
        sqlx::query_as(
            "SELECT id, ticket_id, note_id, file_name, file_size, mime_type, \
                    storage_path, tenant_id, uploaded_by_id, created_by_contact_id, created_at, \
                    is_inline \
             FROM ticket_attachments \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(attachment_id)
        .fetch_optional(&mut *self.db.begin_with_tenant(tenant_id).await?)
        .await?
        .ok_or_else(|| AppError::NotFound("attachment not found".into()))
    }

    /// PMS-941: store an image the author is embedding in a description or a
    /// note, and hand back the public URL to put in the markdown.
    ///
    /// Three things separate this from [`Self::create`], and each one is what
    /// makes a public read of the result defensible:
    ///
    /// 1. The type is checked against `utils::inline_image`, so only PNG, JPEG,
    ///    WebP and GIF reach disk. SVG is refused: it is a script-capable
    ///    document, and this one would be served from the API origin.
    /// 2. `note_id` is NULL. The image is embedded while the text is still
    ///    being written, so there is frequently no note row to attach it to yet.
    /// 3. `is_inline` is set, which is the only thing the public read looks for.
    pub async fn create_inline(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
        file_name: String,
        mime_type: String,
        bytes: Vec<u8>,
        uploaded_by: Uuid,
    ) -> AppResult<AttachmentResponse> {
        let mime = check_inline_image_mime(&mime_type)?;
        if bytes.is_empty() {
            return Err(AppError::BadRequest("The uploaded file is empty".into()));
        }
        let cap = inline_cap(self.config.max_bytes);
        if bytes.len() as u64 > cap {
            return Err(AppError::PayloadTooLarge(format!(
                "an inline image exceeds the {cap} byte cap"
            )));
        }
        self.assert_ticket_in_tenant(tenant_id, ticket_id).await?;
        self.insert_blob(
            tenant_id,
            ticket_id,
            None,
            file_name,
            mime.to_string(),
            bytes,
            Some(uploaded_by),
            None,
            true,
        )
        .await
    }

    /// PMS-941: the row behind the PUBLIC inline-image read.
    ///
    /// SAFETY (PMS-285 / PMS-941): this runs on the BYPASSRLS migrator pool
    /// because it has no tenant to set the `app.current_tenant` GUC to. The
    /// caller presents an attachment id and nothing else - no session, no
    /// cookie, no signature - so there is no tenant context to derive. It is
    /// the shape `tenant_intake_tokens` documents in migration 095 and the KB
    /// article image repeats: a lookup whose only identity is the presented
    /// secret is cross-tenant by construction. Every OTHER read of this table
    /// is tenant-scoped through `begin_with_tenant`.
    ///
    /// `is_inline` is in the WHERE clause rather than checked afterwards, so an
    /// unknown id, a deleted attachment and a perfectly real attachment that
    /// was never meant to be public all return exactly the same 404. That last
    /// case is the one that matters: the answer must not tell a caller holding
    /// a guessed uuid that they found something.
    async fn read_public_inline(&self, attachment_id: Uuid) -> AppResult<AttachmentRow> {
        let pool: &PgPool = self.db.migrator_pool();
        sqlx::query_as(
            "SELECT id, ticket_id, note_id, file_name, file_size, mime_type, \
                    storage_path, tenant_id, uploaded_by_id, created_by_contact_id, created_at, \
                    is_inline \
             FROM ticket_attachments \
             WHERE id = $1 AND is_inline",
        )
        .bind(attachment_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("attachment not found".into()))
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
        // delete posture of other modules). PMS-910: addressed by tenant and
        // id rather than by the path the row carried, so a stale or hostile
        // value in that column cannot unlink something else.
        let _ = path;
        let _ = self
            .store
            .delete(&ObjectKey::ticket_attachment(tenant_id, attachment_id))
            .await;
        let _ = self.ledger.forget(tenant_id, attachment_id).await;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum Uploader {
    Agent { user_id: Uuid },
    // Contact-plane retirement fallout; retained pending MAPPS-656/657 restoration decision
    #[allow(dead_code)]
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
        .map_err(|e| AppError::BadRequest(format!("Multipart parse: {e}")))?
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
            .map_err(|e| AppError::BadRequest(format!("Multipart read: {e}")))?;
        return Ok((file_name, mime_type, bytes.to_vec()));
    }
    Err(AppError::BadRequest(
        "Missing 'file' part in multipart body".into(),
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
        // PMS-941: ticket-scoped, note-free, image-only. The upload an author
        // makes while embedding a picture in a description or a note, before
        // there is necessarily a note row to hang it from.
        //
        // Merge note (PMS-936/PMS-941): the original PMS-941 URL was
        // `POST /tickets/{id}/attachments`, but PMS-936 shipped a dual-plane
        // general-attachment handler at that exact URL on the mokosh-contact-
        // login track (JSON body, `tickets:attach_file` gated for contacts,
        // `created_by_contact_id` stamping). Both routes are wanted; both
        // panic axum at Router construction if they share a (method, path).
        // Move the PMS-941 image-only inline upload to
        // `/tickets/{id}/attachments/inline` so the generic attachment URL
        // stays the shared plane and the inline-image contract lives at
        // a URL that names its constraint.
        .route(
            "/tickets/{ticket_id}/attachments/inline",
            post(upload_inline_agent),
        )
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

/// The PUBLIC inline-image read. Mounted by the caller under `/api/v1/public`.
///
/// Its own router because the subtree it lands in is unauthenticated by design;
/// see the "Routing model" section of CLAUDE.md, which requires every handler
/// there to say what it exposes.
pub fn public_ticket_attachment_routes(service: AttachmentService) -> Router {
    let state = AttachmentsRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route(
            "/tickets/attachments/{attachment_id}",
            get(get_public_inline_attachment),
        )
        .with_state(state)
}

// mokosh-contact-login: `portal_attachment_routes` retired with the
// `/portal/*` customer-portal surface. A contact-plane replacement is folded
// into the ticket contact routes in a later prompt.

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

/// PMS-941: UNAUTHENTICATED READ AHEAD. What this handler stores is what
/// `get_public_inline_attachment` will hand to anyone holding the id, so the
/// validation in `create_inline` is the whole of the protection.
async fn upload_inline_agent(
    State(s): State<AttachmentsRouterState>,
    RequireAuth(user): RequireAuth,
    Path(ticket_id): Path<Uuid>,
    multipart: Multipart,
) -> AppResult<Json<AttachmentResponse>> {
    let (file_name, mime_type, bytes) = read_multipart_file(multipart).await?;
    let resp = s
        .service
        .create_inline(
            user.tenant().get(),
            ticket_id,
            file_name,
            mime_type,
            bytes,
            user.id,
        )
        .await?;
    Ok(Json(resp))
}

async fn download_agent(
    State(s): State<AttachmentsRouterState>,
    RequireAuth(user): RequireAuth,
    Path((ticket_id, note_id, attachment_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let tenant_uuid = user.tenant().get();
    s.service
        .assert_note_in_ticket(tenant_uuid, ticket_id, note_id)
        .await?;
    let row = s.service.get_row(tenant_uuid, attachment_id).await?;
    if row.ticket_id != ticket_id || row.note_id != Some(note_id) {
        return Err(AppError::NotFound("attachment not on this note".into()));
    }
    attachment_response(&s.service.store, row, &headers).await
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

// mokosh-contact-login: portal-plane attachment handlers (list_portal,
// upload_portal, download_portal, delete_portal) retired with the /portal/*
// customer-portal surface. A contact-plane replacement lands in a later prompt.

/// UNAUTHENTICATED. The id in the path is the only identity; see the module
/// header for why an `<img>` leaves no other option, and `read_public_inline`
/// for why a non-inline attachment 404s here rather than being served.
async fn get_public_inline_attachment(
    State(s): State<AttachmentsRouterState>,
    Path(attachment_id): Path<Uuid>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let row = s.service.read_public_inline(attachment_id).await?;
    inline_image_response(&s.service.store, row, &headers).await
}

/// Strong validator for an immutable blob: the uuid that addresses it plus the
/// size recorded on the row. Deliberately not a content hash, because hashing
/// would read the whole file to answer a conditional request, which is the very
/// cost this change removes.
fn attachment_etag(id: Uuid, file_size: i32) -> String {
    format!("\"{id}-{file_size}\"")
}

/// RFC 9110 compares `If-None-Match` with the WEAK function, so `W/"x"` matches
/// `"x"`, `*` matches any existing representation, and the value may be a list.
fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    // A missing or non-ASCII header is "no usable validator", which the
    // standard lets a server treat as no conditional request at all: the caller
    // then gets the full 200 it would have got anyway, so nothing is hidden.
    let Some(raw) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    raw.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

/// PMS-783: stream the blob and let the client revalidate.
///
/// The body is a `ReaderStream` over the open file, so the response holds one
/// chunk at a time instead of the whole attachment; `content-length` comes from
/// the row rather than from a buffer. A conditional request that already has
/// the bytes gets a 304 without the file ever being opened.
async fn attachment_response(
    store: &LocalStore,
    row: AttachmentRow,
    headers: &HeaderMap,
) -> AppResult<Response> {
    let etag = attachment_etag(row.id, row.file_size);
    if if_none_match_matches(headers, &etag) {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::CACHE_CONTROL, CACHE_CONTROL_VALUE.to_string()),
                (header::ETAG, etag),
            ],
        )
            .into_response());
    }

    let attachment_id = row.id;
    let file = store
        .open(&ObjectKey::ticket_attachment(row.tenant_id, row.id))
        .await
        .map_err(|e| AppError::Internal(format!("attachment blob missing: {e}")))?;
    // A read that fails mid-body aborts the response (the declared
    // content-length is never reached), which the client sees as a truncated
    // download; log the cause so the failure is diagnosable server-side too.
    let stream = ReaderStream::new(file).map(move |chunk| {
        chunk.inspect_err(|e| {
            tracing::error!(%attachment_id, "attachment stream read failed: {e}");
        })
    });

    let disposition = format!(
        "attachment; filename=\"{}\"",
        row.file_name.replace('"', "")
    );
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, row.mime_type),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CONTENT_LENGTH, row.file_size.to_string()),
            (header::CACHE_CONTROL, CACHE_CONTROL_VALUE.to_string()),
            (header::ETAG, etag),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

/// PMS-941: the same streaming body as [`attachment_response`], with the three
/// header differences a public image needs.
///
/// No `Content-Disposition`: the private download declares `attachment` so a
/// browser saves the file, which is exactly wrong for an `<img>`. `Cache-Control`
/// is `public`, because there is no session to keep a shared cache out. And
/// `X-Content-Type-Options: nosniff`, because the bytes are user-supplied and a
/// browser must render them as the declared type rather than sniffing its way
/// to something scriptable - the upload allowlist and this header are two
/// halves of one guarantee.
async fn inline_image_response(
    store: &LocalStore,
    row: AttachmentRow,
    headers: &HeaderMap,
) -> AppResult<Response> {
    let etag = attachment_etag(row.id, row.file_size);
    if if_none_match_matches(headers, &etag) {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                (
                    header::CACHE_CONTROL,
                    INLINE_CACHE_CONTROL_VALUE.to_string(),
                ),
                (header::ETAG, etag),
            ],
        )
            .into_response());
    }

    let attachment_id = row.id;
    // A row whose blob is gone must not become a 500 on a route the whole
    // internet can reach: it is the same "no such image" the caller would get
    // for an unknown id, so answer it the same way.
    let file = store
        .open(&ObjectKey::ticket_attachment(row.tenant_id, row.id))
        .await
        .map_err(|e| {
            tracing::warn!(%attachment_id, "inline attachment blob missing: {e}");
            AppError::NotFound("attachment not found".into())
        })?;
    let stream = ReaderStream::new(file).map(move |chunk| {
        chunk.inspect_err(|e| {
            tracing::error!(%attachment_id, "inline attachment stream read failed: {e}");
        })
    });

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, row.mime_type),
            (header::CONTENT_LENGTH, row.file_size.to_string()),
            (
                header::CACHE_CONTROL,
                INLINE_CACHE_CONTROL_VALUE.to_string(),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::ETAG, etag),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(if_none_match: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::IF_NONE_MATCH, if_none_match.parse().unwrap());
        h
    }

    #[test]
    fn an_etag_is_the_uuid_and_the_size() {
        let id = Uuid::nil();
        assert_eq!(
            attachment_etag(id, 42),
            "\"00000000-0000-0000-0000-000000000000-42\""
        );
        assert_ne!(
            attachment_etag(id, 42),
            attachment_etag(id, 43),
            "a differently-sized blob must not validate against a cached copy"
        );
    }

    #[test]
    fn if_none_match_honours_weak_lists_and_star() {
        let etag = attachment_etag(Uuid::nil(), 7);
        assert!(if_none_match_matches(&headers_with(&etag), &etag));
        assert!(if_none_match_matches(
            &headers_with(&format!("W/{etag}")),
            &etag
        ));
        assert!(if_none_match_matches(
            &headers_with(&format!("\"other\", {etag}")),
            &etag
        ));
        assert!(if_none_match_matches(&headers_with("*"), &etag));
        assert!(!if_none_match_matches(&headers_with("\"other\""), &etag));
        assert!(
            !if_none_match_matches(&HeaderMap::new(), &etag),
            "no header means no conditional request, so never a 304"
        );
    }

    fn row(id: Uuid, is_inline: bool) -> AttachmentRow {
        AttachmentRow {
            id,
            ticket_id: Uuid::nil(),
            note_id: None,
            file_name: "shot.png".into(),
            file_size: 12,
            mime_type: "image/png".into(),
            storage_path: "/data/attachments/x".into(),
            tenant_id: Uuid::nil(),
            uploaded_by_id: None,
            created_by_contact_id: None,
            created_at: Utc::now(),
            is_inline,
        }
    }

    #[test]
    fn an_inline_path_is_relative_so_a_client_joins_its_own_base() {
        let id = Uuid::new_v4();
        let path = inline_attachment_path(id);
        assert_eq!(path, format!("/api/v1/public/tickets/attachments/{id}"));
        assert!(!path.starts_with("http"), "nothing here knows the API base");
    }

    /// PMS-941: a URL in the response is a promise the public route keeps.
    /// Every other attachment in this table 404s there, so advertising a URL
    /// for one would be telling the client to fetch something that does not
    /// answer - and, worse, would read as though the file were public.
    #[test]
    fn only_an_inline_row_advertises_a_url() {
        let id = Uuid::new_v4();
        let inline: AttachmentResponse = row(id, true).into();
        assert_eq!(
            inline.url.as_deref(),
            Some(inline_attachment_path(id)).as_deref()
        );
        assert!(inline.is_inline);

        let private: AttachmentResponse = row(id, false).into();
        assert_eq!(
            private.url, None,
            "a note attachment, a portal upload and an email attachment have no \
             public URL, so none may be offered"
        );
        assert!(!private.is_inline);
    }

    #[test]
    fn the_inline_cap_is_a_floor_against_the_configured_cap() {
        assert_eq!(inline_cap(25 * 1024 * 1024), INLINE_MAX_BYTES);
        assert_eq!(
            inline_cap(64 * 1024),
            64 * 1024,
            "an operator who lowers ATTACHMENT_MAX_BYTES lowers this too"
        );
        assert_eq!(
            inline_cap(u64::MAX),
            INLINE_MAX_BYTES,
            "raising the attachment cap must not raise what a public route serves"
        );
    }

    /// The whole security argument for the public route is that it answers for
    /// flagged rows and nothing else, and that the filter is in the query
    /// rather than a check a later edit could reorder around. Guard the shape:
    /// a version that fetched the row first and tested the flag afterwards
    /// would compile and pass every behavioural test written against it.
    #[test]
    fn the_public_read_filters_on_the_flag_in_sql() {
        let body = code_only();
        assert!(
            body.contains("WHERE id = $1 AND is_inline"),
            "read_public_inline must select on is_inline, so an unauthorised \
             row is indistinguishable from an unknown id"
        );
        assert!(
            body.contains("SAFETY (PMS-285"),
            "the migrator-pool read needs its pool-safety note"
        );
    }

    /// A `Content-Disposition: attachment` makes a browser save the file
    /// instead of rendering it, which defeats the entire point of a route whose
    /// caller is an `<img>`. The private download sets that header, so the two
    /// response builders must not converge.
    #[test]
    fn the_inline_response_does_not_tell_a_browser_to_download() {
        let body = code_only();
        let inline = body
            .split_once("async fn inline_image_response(")
            .expect("the inline response builder")
            .1;
        assert!(
            !inline.contains("CONTENT_DISPOSITION"),
            "an <img> must render the bytes, not download them"
        );
        assert!(
            inline.contains("X_CONTENT_TYPE_OPTIONS"),
            "user-supplied bytes served publicly must be nosniff"
        );
    }

    /// The non-test source of this file. Several guards below assert on code
    /// shape, and without the cut they would match their own assertions.
    fn code_only() -> &'static str {
        include_str!("attachments.rs")
            .split_once("mod tests {")
            .expect("this test module")
            .0
    }

    #[test]
    fn a_download_never_buffers_the_whole_blob() {
        // The finding this file fixes (PMS-783 F6) was a `tokio::fs::read` of
        // up to ATTACHMENT_MAX_BYTES on every download. Guard the shape, not
        // just the incident: a re-added whole-file read would compile fine.
        let body = code_only();
        assert!(
            !body.contains("tokio::fs::read("),
            "the download path must stream, not read the blob into a Vec"
        );
        assert!(
            body.contains("Body::from_stream("),
            "the response body must come from a ReaderStream over the open file"
        );
    }
}
