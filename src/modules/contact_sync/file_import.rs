//! PMS-1290 (PSA-70, vCard addendum): an uploaded `.vcf` file, imported
//! through the same preview, review queue and import run as Google Contacts.
//!
//! # One source, many files
//!
//! Every file a tenant uploads imports into ONE `vcard` source row (migration
//! 238), because a card's identity has to survive from one upload to the
//! next: its `UID`, else a digest of its content, is the external id, and the
//! links that remember it are keyed on the source row. Re-importing the same
//! file therefore finds every card already linked and changes nothing, where
//! a row per upload would meet each card as new and create every name-only
//! card again. What differs per upload - the name, who uploaded it, when,
//! what it held - is a `contact_import_files` row that the run, each link and
//! each review snapshot point at, which is where "imported from `{filename}`
//! by `{user}` on `{date}`" comes from.
//!
//! # The flow
//!
//! 1. **Upload** (`upload_vcard`): the bytes are read by [`super::vcard`] on a
//!    blocking thread, refused whole when the file is over a limit, stored at
//!    [`ObjectKind::ContactImport`](crate::storage::ObjectKind::ContactImport),
//!    and previewed against the tenant's contacts with the same
//!    [`ContactSyncEngine::preview`] Google uses. Writes the file row, no
//!    contact.
//! 2. **Preview again** for a chosen set of categories, so the totals are
//!    exact for that choice.
//! 3. **Import** (`import_vcard`): records the chosen categories as the
//!    source's selection and queues a run naming the file. The scheduled
//!    [`super::runs::ContactSyncRunner`] reads the stored file and runs the
//!    engine, exactly as it runs a Google import; nothing about it lives in
//!    the request.
//!
//! # What a file is not
//!
//! A file is not a sync. It is never scheduled, has no credential, and is
//! never a complete listing of anything, so a contact missing from it is not
//! flagged as deleted ([`ContactSyncProvider::lists_everything`]). The stored
//! upload is personal data held only as long as the import needs it: it is
//! discarded when the run ends, and a day after upload regardless.

use std::collections::BTreeSet;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceGroup, SourceResult, UNGROUPED_ID,
};
use super::runs::{RunStatus, RUN_COLUMNS};
use super::service::ContactSyncService;
use super::sync::{ContactSyncEngine, ImportPreview};
use super::vcard::{read_vcards, CardProblem, Limits, ReadError, VcardFile};
use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::storage::ObjectKey;
use crate::utils::error::{AppError, AppResult};
use crate::utils::text::sanitize_invisible;
use crate::utils::upload_limits::oversized_upload_error;

/// `contact_sync_connections.provider` for an uploaded file.
pub const VCARD: &str = "vcard";

/// How long an upload is held when nobody imports it.
pub const HOLD_HOURS: i64 = 24;

/// The name "No category" is shown under.
const UNGROUPED_NAME: &str = "No category";

/// A file name as it is shown. Longer is cut, not refused.
const FILENAME_MAX: usize = 200;

/// The largest upload, the body limit the route sets from it, and the reader's
/// own limit: one number.
pub fn max_upload_bytes() -> u64 {
    Limits::DEFAULT.max_file_bytes
}

/// A parsed file, served as a [`ContactSyncProvider`] so the engine that
/// imports a Google account imports it unchanged.
pub struct VcardFileSource {
    contacts: Vec<SourceContact>,
    groups: Vec<SourceGroup>,
}

impl VcardFileSource {
    /// Records with no `CATEGORIES` carry [`UNGROUPED_ID`], offered as its own
    /// group, so a file with no categories at all can still be imported.
    pub fn new(file: VcardFile) -> Self {
        let mut contacts = file.contacts;
        let mut ungrouped = 0u32;
        for contact in &mut contacts {
            if contact.group_ids.is_empty() {
                contact.group_ids.push(UNGROUPED_ID.to_string());
                ungrouped += 1;
            }
        }
        let mut groups = file.groups;
        if ungrouped > 0 {
            groups.push(SourceGroup {
                id: UNGROUPED_ID.to_string(),
                name: UNGROUPED_NAME.to_string(),
                member_count: Some(ungrouped),
            });
        }
        Self { contacts, groups }
    }

    pub fn groups(&self) -> &[SourceGroup] {
        &self.groups
    }
}

#[async_trait]
impl ContactSyncProvider for VcardFileSource {
    fn id(&self) -> &'static str {
        VCARD
    }

    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>> {
        Ok(self.groups.clone())
    }

    async fn changes_since(&self, _sync_token: Option<&str>) -> SourceResult<SourceChanges> {
        Ok(SourceChanges {
            contacts: self.contacts.clone(),
            next_sync_token: None,
            was_full_resync: false,
        })
    }

    fn lists_everything(&self) -> bool {
        false
    }
}

/// One upload, as the wizard and the upload list show it.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ImportFileView {
    pub id: Uuid,
    pub filename: String,
    pub byte_size: i64,
    pub uploaded_by_user_id: Option<Uuid>,
    pub uploaded_by_name: Option<String>,
    pub uploaded_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The stored bytes are gone: imported, cancelled, or expired. The row
    /// stays, because links name it.
    pub discarded_at: Option<DateTime<Utc>>,
    /// Every `BEGIN:VCARD` in the file.
    pub cards: i32,
    pub contacts: i32,
    /// Cards describing a group, not a person.
    pub group_cards: i32,
    /// Cards that will not import, each with its number, line and reason.
    pub failures: serde_json::Value,
    /// Cards that will import, with something worth saying.
    pub warnings: serde_json::Value,
    /// The file's categories, `No category` included when any card has none.
    pub groups: serde_json::Value,
    /// The run importing it, when one was started.
    #[sqlx(skip)]
    pub latest_run: Option<RunStatus>,
}

const FILE_COLUMNS: &str = "f.id, f.filename, f.byte_size, f.uploaded_by_user_id, \
     NULLIF(TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')), '') \
         AS uploaded_by_name, \
     f.uploaded_at, f.expires_at, f.discarded_at, f.cards, f.contacts, f.group_cards, \
     f.failures, f.warnings, f.groups";

/// What an upload answers: the stored file and what importing it would do.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadedFile {
    pub file: ImportFileView,
    pub preview: ImportPreview,
}

/// A browser's file name, reduced to something safe to show: the last path
/// segment, no control or invisible characters, cut to fit.
fn clean_filename(raw: Option<&str>) -> String {
    let raw = raw.unwrap_or_default();
    let last = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let clean: String = sanitize_invisible(last)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        "contacts.vcf".to_string()
    } else {
        trimmed.chars().take(FILENAME_MAX).collect()
    }
}

/// Read a file on a blocking thread: parsing is CPU work over up to the file
/// limit, and the async executor must not wait on it.
async fn parse(bytes: Vec<u8>) -> AppResult<VcardFile> {
    tokio::task::spawn_blocking(move || read_vcards(bytes.as_slice(), Limits::DEFAULT))
        .await
        .map_err(|e| AppError::Internal(format!("the vCard reader stopped: {e}")))?
        .map_err(|e| match e {
            ReadError::FileTooLarge { limit_bytes } => {
                oversized_upload_error("vCard file", limit_bytes)
            }
            other => AppError::validation_field("file", other.to_string()),
        })
}

/// The stored upload, read and parsed. What the runner imports from.
pub async fn load_source(tenant_id: TenantId, file_id: Uuid) -> AppResult<VcardFileSource> {
    let bytes = crate::storage::shared()
        .read(&ObjectKey::contact_import(tenant_id.get(), file_id))
        .await
        .map_err(|_| {
            AppError::Conflict(
                "The uploaded file is no longer held. Upload it again to import it.".to_string(),
            )
        })?;
    Ok(VcardFileSource::new(parse(bytes).await?))
}

/// Delete a held upload and stamp its row. Idempotent: an object already gone
/// is not an error, and a stamped row is left alone.
pub async fn discard(db: &Database, tenant_id: TenantId, file_id: Uuid) -> AppResult<()> {
    let key = ObjectKey::contact_import(tenant_id.get(), file_id);
    let storage = crate::storage::shared();
    if storage.exists(&key).await? {
        storage.delete(&key).await?;
    }
    let mut tx = db.begin_with_tenant(tenant_id).await?;
    let stamped = sqlx::query(
        "UPDATE contact_import_files SET discarded_at = NOW() \
         WHERE tenant_id = $1 AND id = $2 AND discarded_at IS NULL",
    )
    .bind(tenant_id)
    .bind(file_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if stamped > 0 {
        audit_write(
            &mut *tx,
            tenant_id,
            &AuditCtx::system(tenant_id.get()),
            AuditAction::Update,
            "contact_import_files",
            Some(file_id),
            None,
            Some(serde_json::json!({ "event": "contact_sync.file_discarded" })),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Every held upload past its hold with no run still reading it, across every
/// tenant. The runner calls this each tick.
pub async fn discard_expired(db: &Database) -> AppResult<u64> {
    let expired: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT f.tenant_id, f.id FROM contact_import_files f \
         WHERE f.discarded_at IS NULL AND f.expires_at <= NOW() \
           AND NOT EXISTS (SELECT 1 FROM contact_sync_runs r \
                           WHERE r.import_file_id = f.id AND r.status IN ('queued', 'running')) \
         ORDER BY f.expires_at LIMIT 100",
    )
    // SAFETY (PMS-285): the sweep spans every tenant, the way the runner's own
    // recovery does. Each discard then runs on its row's tenant.
    .fetch_all(db.migrator_pool())
    .await?;
    let mut discarded = 0;
    for (tenant_id, file_id) in expired {
        match discard(db, TenantId::from_trusted(tenant_id), file_id).await {
            Ok(()) => discarded += 1,
            Err(e) => tracing::warn!(
                file_id = %file_id,
                "contact import: could not discard an expired upload: {e}"
            ),
        }
    }
    Ok(discarded)
}

impl ContactSyncService {
    /// The tenant's `vcard` source row, created on first use.
    async fn vcard_source_id(&self, tenant_id: TenantId, user_id: Option<Uuid>) -> AppResult<Uuid> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO contact_sync_connections \
             (tenant_id, provider, connected_by_user_id, account_email, sync_status) \
             VALUES ($1, $2, $3, 'vCard files', 'never') \
             ON CONFLICT (tenant_id, provider) WHERE disconnected_at IS NULL DO NOTHING",
        )
        .bind(tenant_id)
        .bind(VCARD)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        let id: Uuid = sqlx::query_scalar(
            "SELECT id FROM contact_sync_connections \
             WHERE tenant_id = $1 AND provider = $2 AND disconnected_at IS NULL",
        )
        .bind(tenant_id)
        .bind(VCARD)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Store an uploaded `.vcf` and preview importing it. Writes no contact.
    pub async fn upload_vcard(
        &self,
        tenant_id: TenantId,
        filename: Option<&str>,
        bytes: Vec<u8>,
        ctx: &AuditCtx,
    ) -> AppResult<UploadedFile> {
        if bytes.is_empty() {
            return Err(AppError::validation_field("file", "The file is empty."));
        }
        if bytes.len() as u64 > max_upload_bytes() {
            return Err(oversized_upload_error("vCard file", max_upload_bytes()));
        }
        let filename = clean_filename(filename);
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let byte_size = bytes.len() as i64;
        let stored = bytes.clone();
        let parsed = parse(bytes).await?;
        if parsed.cards == 0 {
            return Err(AppError::validation_field(
                "file",
                "This file holds no contacts: it has no BEGIN:VCARD. Export the contacts as a vCard (.vcf) file and upload that.",
            ));
        }
        let problems = |list: &[CardProblem]| serde_json::to_value(list).unwrap_or_default();
        let failures = problems(&parsed.failures);
        let warnings = problems(&parsed.warnings);
        let (cards, contact_count, group_cards) = (
            parsed.cards as i32,
            parsed.contacts.len() as i32,
            parsed.group_cards as i32,
        );
        let source = VcardFileSource::new(parsed);
        let groups = serde_json::to_value(
            source
                .groups()
                .iter()
                .map(|g| serde_json::json!({ "id": g.id, "name": g.name, "member_count": g.member_count }))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();

        let connection_id = self.vcard_source_id(tenant_id, ctx.user_id).await?;
        let file_id = Uuid::new_v4();
        // Bytes first, then the row naming them: a row pointing at an object
        // that is not there is the one ordering that can lie (PMS-957).
        crate::storage::shared()
            .put(
                &ObjectKey::contact_import(tenant_id.get(), file_id),
                &stored,
            )
            .await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO contact_import_files \
             (id, tenant_id, connection_id, filename, byte_size, sha256, uploaded_by_user_id, \
              cards, contacts, group_cards, failures, warnings, groups, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(file_id)
        .bind(tenant_id)
        .bind(connection_id)
        .bind(&filename)
        .bind(byte_size)
        .bind(&digest)
        .bind(ctx.user_id)
        .bind(cards)
        .bind(contact_count)
        .bind(group_cards)
        .bind(&failures)
        .bind(&warnings)
        .bind(&groups)
        .bind(Utc::now() + Duration::hours(HOLD_HOURS))
        .execute(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "contact_import_files",
            Some(file_id),
            None,
            Some(serde_json::json!({
                "event": "contact_sync.file_uploaded",
                "filename": filename,
                "cards": cards,
                "contacts": contact_count,
                "failed_cards": parsed_failed(&failures),
            })),
        )
        .await?;
        tx.commit().await?;

        let preview = ContactSyncEngine::new(self.db.clone())
            .preview(tenant_id, connection_id, &source, None)
            .await?;
        Ok(UploadedFile {
            file: self.vcard_file(tenant_id, file_id).await?,
            preview,
        })
    }

    /// One upload, with the run importing it if there is one.
    pub async fn vcard_file(
        &self,
        tenant_id: TenantId,
        file_id: Uuid,
    ) -> AppResult<ImportFileView> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let mut file: ImportFileView = sqlx::query_as(&format!(
            "SELECT {FILE_COLUMNS} FROM contact_import_files f \
             LEFT JOIN users u ON u.id = f.uploaded_by_user_id \
             WHERE f.tenant_id = $1 AND f.id = $2"
        ))
        .bind(tenant_id)
        .bind(file_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Uploaded file".to_string()))?;
        file.latest_run = sqlx::query_as(&format!(
            "SELECT {RUN_COLUMNS} FROM contact_sync_runs \
             WHERE tenant_id = $1 AND import_file_id = $2 ORDER BY created_at DESC LIMIT 1"
        ))
        .bind(tenant_id)
        .bind(file_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(file)
    }

    /// Recent uploads, newest first.
    pub async fn vcard_files(
        &self,
        tenant_id: TenantId,
        limit: i64,
    ) -> AppResult<Vec<ImportFileView>> {
        let ids: Vec<Uuid> = {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query_scalar(
                "SELECT id FROM contact_import_files WHERE tenant_id = $1 \
                 ORDER BY uploaded_at DESC LIMIT $2",
            )
            .bind(tenant_id)
            .bind(limit.clamp(1, 50))
            .fetch_all(&mut *tx)
            .await?
        };
        let mut files = Vec::with_capacity(ids.len());
        for id in ids {
            files.push(self.vcard_file(tenant_id, id).await?);
        }
        Ok(files)
    }

    /// A held upload that can still be imported.
    async fn held_file(&self, tenant_id: TenantId, file_id: Uuid) -> AppResult<ImportFileView> {
        let file = self.vcard_file(tenant_id, file_id).await?;
        if file.discarded_at.is_some() || file.expires_at <= Utc::now() {
            return Err(AppError::Conflict(
                "This upload is no longer held. Upload the file again to import it.".to_string(),
            ));
        }
        Ok(file)
    }

    /// Preview a held upload for a set of categories, so the totals are exact
    /// for that choice. `None` previews every category.
    pub async fn preview_vcard(
        &self,
        tenant_id: TenantId,
        file_id: Uuid,
        group_ids: Option<&[String]>,
    ) -> AppResult<ImportPreview> {
        self.held_file(tenant_id, file_id).await?;
        let source = load_source(tenant_id, file_id).await?;
        let connection_id = self.vcard_source_id(tenant_id, None).await?;
        let selection: Option<BTreeSet<String>> =
            group_ids.map(|ids| ids.iter().map(|g| g.trim().to_string()).collect());
        ContactSyncEngine::new(self.db.clone())
            .preview(tenant_id, connection_id, &source, selection.as_ref())
            .await
    }

    /// Import a held upload's chosen categories. 202-shaped: the answer is the
    /// run to poll.
    pub async fn import_vcard(
        &self,
        tenant_id: TenantId,
        file_id: Uuid,
        group_ids: &[String],
        ctx: &AuditCtx,
    ) -> AppResult<RunStatus> {
        let file = self.held_file(tenant_id, file_id).await?;
        let offered: BTreeSet<String> = file
            .groups
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|g| g.get("id").and_then(|v| v.as_str()).map(str::to_string))
            .collect();
        let mut chosen: Vec<String> = group_ids.iter().map(|g| g.trim().to_string()).collect();
        chosen.sort();
        chosen.dedup();
        // An empty choice is "not chosen yet", never "the whole file"
        // (PSA-70 E), the rule the Google selection keeps.
        if chosen.is_empty() || chosen.iter().any(|g| !offered.contains(g)) {
            return Err(AppError::validation_field(
                "group_ids",
                "choose at least one of this file's categories",
            ));
        }
        let connection_id = self.vcard_source_id(tenant_id, ctx.user_id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // The selection lives on the source row for the run to read. Only one
        // run per source can be active (migration 229's index), so it cannot
        // change under a run that is reading it.
        let run: RunStatus = sqlx::query_as(&format!(
            "WITH selected AS ( \
                 UPDATE contact_sync_connections SET selected_groups = $5, updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2 \
                   AND NOT EXISTS (SELECT 1 FROM contact_sync_runs r \
                                   WHERE r.connection_id = $2 AND r.status IN ('queued', 'running')) \
                 RETURNING id) \
             INSERT INTO contact_sync_runs \
                 (tenant_id, connection_id, trigger, requested_by_user_id, import_file_id) \
             SELECT $1, id, 'manual', $3, $4 FROM selected \
             RETURNING {RUN_COLUMNS}"
        ))
        .bind(tenant_id)
        .bind(connection_id)
        .bind(ctx.user_id)
        .bind(file_id)
        .bind(serde_json::json!(chosen))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| match e.as_database_error().and_then(|d| d.code()).as_deref() {
            Some("23505") => busy(),
            _ => e.into(),
        })?
        .ok_or_else(busy)?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "contact_sync_runs",
            Some(run.id),
            None,
            Some(serde_json::json!({
                "event": "contact_sync.run_queued",
                "trigger": "manual",
                "provider": VCARD,
                "import_file_id": file_id,
                "filename": file.filename,
                "selected_groups": chosen,
            })),
        )
        .await?;
        tx.commit().await?;
        Ok(run)
    }
}

fn busy() -> AppError {
    AppError::Conflict(
        "A file import is already queued or running. Wait for it to finish, then import this one."
            .to_string(),
    )
}

fn parsed_failed(failures: &serde_json::Value) -> usize {
    failures.as_array().map_or(0, Vec::len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_file_name_is_reduced_to_something_safe_to_show() {
        assert_eq!(
            clean_filename(Some("C:\\Users\\me\\Contacts.vcf")),
            "Contacts.vcf"
        );
        assert_eq!(clean_filename(Some("../../etc/passwd")), "passwd");
        assert_eq!(clean_filename(Some("a\u{200B}b\u{0007}.vcf")), "ab.vcf");
        assert_eq!(clean_filename(None), "contacts.vcf");
        assert_eq!(clean_filename(Some("   ")), "contacts.vcf");
        assert_eq!(
            clean_filename(Some(&"x".repeat(500))).chars().count(),
            FILENAME_MAX
        );
    }

    /// Cards with no category are importable through "No category", and only
    /// those cards carry it.
    #[tokio::test]
    async fn uncategorised_cards_are_offered_as_their_own_group() {
        let file = read_vcards(
            &b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:A\r\nCATEGORIES:Client\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nFN:B\r\nEND:VCARD\r\n"[..],
            Limits::DEFAULT,
        )
        .expect("readable");
        let source = VcardFileSource::new(file);
        let groups: Vec<_> = source
            .list_groups()
            .await
            .expect("groups")
            .into_iter()
            .map(|g| (g.id, g.member_count))
            .collect();
        assert_eq!(
            groups,
            vec![
                ("Client".to_string(), Some(1)),
                (UNGROUPED_ID.to_string(), Some(1))
            ]
        );
        let changes = source.changes_since(None).await.expect("changes");
        assert_eq!(changes.contacts[0].group_ids, vec!["Client"]);
        assert_eq!(changes.contacts[1].group_ids, vec![UNGROUPED_ID]);
        assert!(!source.lists_everything());
        assert!(!changes.was_full_resync && changes.next_sync_token.is_none());
    }
}
