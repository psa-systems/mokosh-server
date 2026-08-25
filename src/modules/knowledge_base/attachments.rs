//! Images a KB article can embed (PMS-923).
//!
//! ## Why the read path is public
//!
//! An image in article markdown is fetched by the browser as `<img src="...">`.
//! An `<img>` cannot carry an `Authorization` header, and the SPA authenticates
//! with a bearer token rather than a cookie, so the URL that serves the bytes
//! cannot sit behind the auth middleware. The attachment's v4 UUID is therefore
//! the only credential: 122 bits of randomness, unguessable, and enough to
//! fetch the file.
//!
//! That is a real cost and it is stated rather than buried: anyone holding the
//! URL can fetch the image, including for an `internal` or `client_specific`
//! article. It is the same bargain the tenant logo already makes (a recipient's
//! mail client fetches it out of an email and can never authenticate) and the
//! same one the request-form magic link makes. The alternative is storing an
//! opaque reference in the markdown and minting a short-lived signed URL at
//! render time; that touches the renderer and is tracked on PMS-923 rather than
//! assumed here.
//!
//! ## Storage
//!
//! Bytes live on disk under `ATTACHMENT_DIR`, in a `kb-articles/` subdirectory
//! so an article image can never collide with the `{tenant_id}/{attachment_id}`
//! path ticket attachments use, exactly as `tenant-logos/` does.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::{RequireManager, TenantId, TenantScoped};
use crate::utils::error::{AppError, AppResult};

/// Image types an article may embed.
///
/// SVG is deliberately absent, for the same reason it is absent from the tenant
/// logo list: it is a script-capable document, and this one is served from the
/// API origin to unauthenticated clients.
const ALLOWED_MIME: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

/// Default cap when `KB_ATTACHMENT_MAX_BYTES` is unset. 5 MiB: generous for a
/// screenshot or a diagram, well under the 25 MiB a ticket attachment allows,
/// because these are embedded in a page rather than downloaded on purpose.
const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// Subdirectory under the shared upload root, so an article image cannot
/// collide with a ticket attachment's `{tenant_id}/{attachment_id}` path.
const SUBDIR: &str = "kb-articles";

#[derive(Clone, Debug)]
pub struct KbAttachmentConfig {
    pub dir: PathBuf,
    pub max_bytes: u64,
}

impl KbAttachmentConfig {
    pub fn from_env() -> Self {
        let root = std::env::var("ATTACHMENT_DIR")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "/data/attachments".to_string());
        let max_bytes = std::env::var("KB_ATTACHMENT_MAX_BYTES")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_BYTES);
        Self {
            dir: PathBuf::from(root).join(SUBDIR),
            max_bytes,
        }
    }

    fn path_for(&self, id: Uuid) -> PathBuf {
        self.dir.join(id.to_string())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KbAttachmentResponse {
    pub id: Uuid,
    pub article_id: Uuid,
    pub file_name: String,
    pub mime_type: String,
    pub file_size: i64,
    pub created_at: DateTime<Utc>,
    /// Where to point an `<img>`. Relative on purpose: the SPA joins it with
    /// the API base it already knows, and nothing here can know that base.
    pub url: String,
}

/// The path a client fetches an attachment from.
pub fn attachment_path(id: Uuid) -> String {
    format!("/api/v1/public/kb/attachments/{id}")
}

fn check_mime(mime: &str) -> AppResult<&str> {
    ALLOWED_MIME
        .iter()
        .find(|m| **m == mime)
        .copied()
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "Unsupported image type '{mime}'. Allowed: {}",
                ALLOWED_MIME.join(", ")
            ))
        })
}

#[derive(Clone)]
pub struct KbAttachmentService {
    db: Database,
    config: KbAttachmentConfig,
}

impl KbAttachmentService {
    pub fn new(db: Database, config: KbAttachmentConfig) -> Self {
        Self { db, config }
    }

    /// Store an image against an article the caller can reach.
    pub async fn create(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        file_name: String,
        mime_type: String,
        bytes: Vec<u8>,
        uploaded_by: Uuid,
    ) -> AppResult<KbAttachmentResponse> {
        let mime = check_mime(&mime_type)?;
        if bytes.is_empty() {
            return Err(AppError::BadRequest("The uploaded file is empty".into()));
        }
        if bytes.len() as u64 > self.config.max_bytes {
            return Err(AppError::BadRequest(format!(
                "Image is larger than the {} KiB limit",
                self.config.max_bytes / 1024
            )));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // The article has to exist in THIS tenant. Checked inside the
        // tenant-scoped transaction, so RLS is what enforces it rather than
        // this predicate being the only thing standing in the way.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM kb_articles WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(article_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(AppError::NotFound("Article".to_string()));
        }

        let row: (Uuid, DateTime<Utc>) = sqlx::query_as(
            r#"
            INSERT INTO kb_article_attachments
                (tenant_id, article_id, file_name, mime_type, file_size, uploaded_by_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(&file_name)
        .bind(mime)
        .bind(bytes.len() as i64)
        .bind(uploaded_by)
        .fetch_one(&mut *tx)
        .await?;

        // Bytes AFTER the row, and the commit after the bytes: a file with no
        // row is invisible litter, whereas a row with no file is a broken image
        // in a published article.
        tokio::fs::create_dir_all(&self.config.dir)
            .await
            .map_err(|e| AppError::Internal(format!("create kb attachment dir: {e}")))?;
        tokio::fs::write(self.config.path_for(row.0), &bytes)
            .await
            .map_err(|e| AppError::Internal(format!("write kb attachment: {e}")))?;

        tx.commit().await?;

        Ok(KbAttachmentResponse {
            id: row.0,
            article_id,
            file_name,
            mime_type: mime.to_string(),
            file_size: bytes.len() as i64,
            created_at: row.1,
            url: attachment_path(row.0),
        })
    }

    /// Every image on an article, so the editor can offer what is already
    /// uploaded rather than making the author re-upload.
    pub async fn list(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
    ) -> AppResult<Vec<KbAttachmentResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<(Uuid, String, String, i64, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, file_name, mime_type, file_size, created_at \
             FROM kb_article_attachments \
             WHERE tenant_id = $1 AND article_id = $2 \
             ORDER BY created_at DESC, id",
        )
        .bind(tenant_id)
        .bind(article_id)
        .fetch_all(&mut *tx)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, file_name, mime_type, file_size, created_at)| KbAttachmentResponse {
                    id,
                    article_id,
                    file_name,
                    mime_type,
                    file_size,
                    created_at,
                    url: attachment_path(id),
                },
            )
            .collect())
    }

    /// Remove an image, row and file both.
    pub async fn delete(
        &self,
        tenant_id: TenantId,
        article_id: Uuid,
        attachment_id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let res = sqlx::query(
            "DELETE FROM kb_article_attachments \
             WHERE tenant_id = $1 AND article_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(article_id)
        .bind(attachment_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound("Attachment".to_string()));
        }
        tx.commit().await?;
        // Best effort: a file with no row is unreachable, so a failed unlink
        // must not fail the request that already removed the reference.
        let _ = tokio::fs::remove_file(self.config.path_for(attachment_id)).await;
        Ok(())
    }

    /// The bytes for an id, for the PUBLIC read path.
    ///
    /// SAFETY (PMS-285 / PMS-923): this runs on the BYPASSRLS migrator pool
    /// because it has no tenant to set the `app.current_tenant` GUC to. The
    /// caller presents an attachment id and nothing else; there is no session,
    /// so there is no tenant context to derive. That is the same shape
    /// `tenant_intake_tokens` documents in migration 095: a lookup whose only
    /// identity is the presented secret is cross-tenant by construction.
    ///
    /// The id is a v4 UUID, so it is the credential. Every OTHER access to this
    /// table is tenant-scoped through `begin_with_tenant` above.
    async fn read_public(&self, id: Uuid) -> AppResult<(String, Vec<u8>)> {
        let pool: &PgPool = self.db.migrator_pool();
        let mime: Option<String> =
            sqlx::query_scalar("SELECT mime_type FROM kb_article_attachments WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        // An unknown id and a deleted attachment answer identically, so this is
        // not an existence oracle for ids somebody is guessing at.
        let mime = mime.ok_or_else(|| AppError::NotFound("Attachment".to_string()))?;
        let bytes = tokio::fs::read(self.config.path_for(id))
            .await
            .map_err(|_| AppError::NotFound("Attachment".to_string()))?;
        Ok((mime, bytes))
    }
}

#[derive(Clone)]
pub struct KbAttachmentRouterState {
    pub service: Arc<KbAttachmentService>,
}

/// Authenticated routes: upload, list, delete.
pub fn kb_attachment_routes(service: KbAttachmentService) -> Router {
    let state = KbAttachmentRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route(
            "/kb/articles/{id}/attachments",
            get(list_attachments).post(upload_attachment),
        )
        .route(
            "/kb/articles/{id}/attachments/{attachment_id}",
            delete(delete_attachment),
        )
        .with_state(state)
}

/// The PUBLIC read route. Mounted by the caller under `/api/v1/public`.
///
/// Separate router because the subtree it lands in is unauthenticated by
/// design; see the "Routing model" section of CLAUDE.md, which requires every
/// handler there to justify itself.
pub fn public_kb_attachment_routes(service: KbAttachmentService) -> Router {
    let state = KbAttachmentRouterState {
        service: Arc::new(service),
    };
    Router::new()
        .route(
            "/kb/attachments/{attachment_id}",
            get(get_public_attachment),
        )
        .with_state(state)
}

async fn upload_attachment(
    State(s): State<KbAttachmentRouterState>,
    manager: RequireManager,
    Path(article_id): Path<Uuid>,
    mut multipart: Multipart,
) -> AppResult<Json<KbAttachmentResponse>> {
    let user = manager.0;
    let mut found: Option<(String, String, Vec<u8>)> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Multipart parse: {e}")))?
    {
        if field.name().unwrap_or_default() != "file" {
            continue;
        }
        let file_name = field
            .file_name()
            .map(str::to_string)
            .unwrap_or_else(|| "image".to_string());
        let mime_type = field
            .content_type()
            .map(str::to_string)
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let bytes = field
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(format!("Multipart read: {e}")))?;
        found = Some((file_name, mime_type, bytes.to_vec()));
        break;
    }
    let (file_name, mime_type, bytes) = found
        .ok_or_else(|| AppError::BadRequest("Missing 'file' part in multipart body".into()))?;

    Ok(Json(
        s.service
            .create(
                user.tenant(),
                article_id,
                file_name,
                mime_type,
                bytes,
                user.id,
            )
            .await?,
    ))
}

async fn list_attachments(
    State(s): State<KbAttachmentRouterState>,
    manager: RequireManager,
    Path(article_id): Path<Uuid>,
) -> AppResult<Json<Vec<KbAttachmentResponse>>> {
    Ok(Json(s.service.list(manager.0.tenant(), article_id).await?))
}

async fn delete_attachment(
    State(s): State<KbAttachmentRouterState>,
    manager: RequireManager,
    Path((article_id, attachment_id)): Path<(Uuid, Uuid)>,
) -> AppResult<StatusCode> {
    s.service
        .delete(manager.0.tenant(), article_id, attachment_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// UNAUTHENTICATED. The id in the path is the only identity; see the module
/// header for why an `<img>` leaves no other option.
async fn get_public_attachment(
    State(s): State<KbAttachmentRouterState>,
    Path(attachment_id): Path<Uuid>,
) -> AppResult<impl IntoResponse> {
    let (mime, bytes) = s.service.read_public(attachment_id).await?;
    Ok((
        [
            (header::CONTENT_TYPE, mime),
            // Immutable: the id names one set of bytes for its whole life, so a
            // client that has fetched it never needs to ask again.
            (
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
            // The bytes are user-supplied; make certain a browser renders them
            // as the declared type rather than sniffing its way to something
            // scriptable.
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SVG is script-capable and this route serves from the API origin to
    /// unauthenticated clients, so it must never be allowed. Same rule the
    /// tenant logo carries.
    #[test]
    fn svg_is_not_an_allowed_image_type() {
        assert!(check_mime("image/svg+xml").is_err());
        assert!(check_mime("text/html").is_err());
        assert!(check_mime("application/octet-stream").is_err());
        for ok in ALLOWED_MIME {
            assert!(check_mime(ok).is_ok(), "{ok} should be allowed");
        }
    }

    /// The stored path is derived from the id alone, so a `file_name` carrying
    /// `../` cannot reach outside the upload directory.
    #[test]
    fn the_stored_path_comes_from_the_id_not_the_file_name() {
        let config = KbAttachmentConfig {
            dir: PathBuf::from("/data/attachments/kb-articles"),
            max_bytes: 1024,
        };
        let id = Uuid::new_v4();
        let path = config.path_for(id);
        assert_eq!(
            path,
            PathBuf::from("/data/attachments/kb-articles").join(id.to_string()),
            "a traversal in the uploaded name has nothing to traverse, because \
             the name never reaches the path"
        );
    }

    #[test]
    fn the_public_path_is_relative_so_a_client_joins_its_own_base() {
        let id = Uuid::new_v4();
        let path = attachment_path(id);
        assert!(path.starts_with("/api/v1/public/kb/attachments/"));
        assert!(!path.starts_with("http"), "nothing here knows the API base");
    }
}
