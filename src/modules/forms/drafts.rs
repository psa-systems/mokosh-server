//! PMS-759: server-side drafts for the request-form builder.
//!
//! The builder already autosaves to `localStorage` on every change (PMS-754).
//! This is the tier that follows the user to another machine: a snapshot of
//! the editor, owned by one user, upserted on a debounce while they type.
//!
//! The payload is opaque. It is the editor's own shape, and re-declaring that
//! shape here would be a second copy to keep in step for no benefit: the only
//! thing read inside it is `name`, so the drafts list has something to show.
//! Being opaque and client-supplied is also why it is size-capped.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::service::FormsService;
use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

/// Ceiling on a stored snapshot, in bytes of serialised JSON.
///
/// A generous form (60 fields, long help text, an option set on each) lands
/// around 30 KB, so this is roughly eight times the realistic worst case: big
/// enough never to reject real work, small enough that the table cannot be
/// used as free storage. Rejected loudly rather than truncated, because a
/// truncated draft restores as a corrupted form.
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// What the SPA sends on each debounced autosave.
#[derive(Debug, Clone, Deserialize)]
pub struct UpsertFormDraftRequest {
    /// The definition being edited, or `None` while the form is new. This is
    /// the key the draft is stored under, so a user editing two different
    /// forms holds two drafts and neither overwrites the other.
    #[serde(default)]
    pub form_definition_id: Option<Uuid>,
    /// The editor snapshot, as the builder serialises itself.
    pub payload: serde_json::Value,
}

/// A stored draft, as the drafts list and the editor both read it.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FormDraftResponse {
    pub id: Uuid,
    pub form_definition_id: Option<Uuid>,
    /// `payload -> name`, lifted out so the list has a label without every row
    /// carrying its whole snapshot. Empty when the draft has not been named
    /// yet, which is normal: a user types fields before they type a title.
    pub name: Option<String>,
    pub payload: serde_json::Value,
    /// What makes "the newer copy wins" decidable when the browser also holds
    /// a local draft.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl FormsService {
    /// Every draft belonging to one user, most recently touched first.
    ///
    /// Scoped by tenant (RLS, via `begin_with_tenant`) and by user (the
    /// predicate below). Drafts are private working state: another user in the
    /// same tenant must not see a half-built form, so ownership is a filter on
    /// every read, not a check applied after fetching.
    pub async fn list_form_drafts(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> AppResult<Vec<FormDraftResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, FormDraftResponse>(
            "SELECT id, form_definition_id, payload ->> 'name' AS name, payload, updated_at \
             FROM form_definition_drafts \
             WHERE tenant_id = $1 AND user_id = $2 \
             ORDER BY updated_at DESC",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(rows)
    }

    /// Write the caller's draft for one form, replacing whatever they had.
    ///
    /// An upsert rather than a read-then-write: autosave fires while the user
    /// types, so two writes can overlap, and the partial unique indexes from
    /// migration 105 turn that race into a second `UPDATE` instead of a
    /// duplicate row or a 409 on a best-effort save.
    ///
    /// The two branches exist because the uniqueness that has to hold is
    /// different: one draft per (user, definition) for an existing form, and
    /// one "new form" draft per user. `ON CONFLICT` infers a partial index
    /// only when given that index's predicate, so each branch names its own.
    pub async fn upsert_form_draft(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        req: &UpsertFormDraftRequest,
    ) -> AppResult<FormDraftResponse> {
        // Measured on the serialised form, which is what is stored and what a
        // caller controls, rather than on any in-memory size.
        let size = serde_json::to_vec(&req.payload)
            .map_err(|e| AppError::BadRequest(format!("draft payload is not storable: {e}")))?
            .len();
        if size > MAX_PAYLOAD_BYTES {
            return Err(AppError::BadRequest(format!(
                "That draft is too large to save ({size} bytes; the limit is {MAX_PAYLOAD_BYTES})"
            )));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // The definition has to belong to this tenant. RLS already scopes the
        // draft row, but without this a caller could file a draft against
        // another tenant's definition id and get it back on every list, which
        // leaks that the id exists.
        if let Some(definition_id) = req.form_definition_id {
            let exists: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM form_definitions WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(definition_id)
            .fetch_optional(&mut *tx)
            .await?;
            if exists.is_none() {
                return Err(AppError::NotFound("Form".to_string()));
            }
        }

        let returning =
            "RETURNING id, form_definition_id, payload ->> 'name' AS name, payload, updated_at";
        let row = match req.form_definition_id {
            Some(definition_id) => {
                sqlx::query_as::<_, FormDraftResponse>(&format!(
                    "INSERT INTO form_definition_drafts (tenant_id, user_id, form_definition_id, payload) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (tenant_id, user_id, form_definition_id) WHERE form_definition_id IS NOT NULL \
                     DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW() {returning}"
                ))
                .bind(tenant_id)
                .bind(user_id)
                .bind(definition_id)
                .bind(&req.payload)
                .fetch_one(&mut *tx)
                .await?
            }
            None => {
                sqlx::query_as::<_, FormDraftResponse>(&format!(
                    "INSERT INTO form_definition_drafts (tenant_id, user_id, form_definition_id, payload) \
                     VALUES ($1, $2, NULL, $3) \
                     ON CONFLICT (tenant_id, user_id) WHERE form_definition_id IS NULL \
                     DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW() {returning}"
                ))
                .bind(tenant_id)
                .bind(user_id)
                .bind(&req.payload)
                .fetch_one(&mut *tx)
                .await?
            }
        };
        tx.commit().await?;
        Ok(row)
    }

    /// Discard one draft.
    ///
    /// `user_id` is part of the predicate rather than checked afterwards, so a
    /// draft belonging to someone else is a 404 and not a 403: the caller
    /// should not learn that the id exists.
    pub async fn delete_form_draft(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        draft_id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let deleted = sqlx::query(
            "DELETE FROM form_definition_drafts WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(draft_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if deleted == 0 {
            return Err(AppError::NotFound("Draft".to_string()));
        }
        Ok(())
    }

    /// Drop the draft a just-saved form no longer needs.
    ///
    /// Called from the create/update paths rather than left to the SPA: the
    /// draft exists to survive the browser going away, so "the browser will
    /// clean it up" is the one assumption it cannot make. Best-effort, since
    /// the definition is already written and a stale draft is a nuisance
    /// rather than a fault.
    pub async fn clear_form_draft_after_save(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        form_definition_id: Option<Uuid>,
    ) {
        let result = async {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            match form_definition_id {
                Some(id) => {
                    sqlx::query(
                        "DELETE FROM form_definition_drafts \
                         WHERE tenant_id = $1 AND user_id = $2 AND form_definition_id = $3",
                    )
                    .bind(tenant_id)
                    .bind(user_id)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                }
                None => {
                    sqlx::query(
                        "DELETE FROM form_definition_drafts \
                         WHERE tenant_id = $1 AND user_id = $2 AND form_definition_id IS NULL",
                    )
                    .bind(tenant_id)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            tx.commit().await
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = ?e, "could not clear the form draft after a save");
        }
    }
}
