//! PMS-957: one row per stored file, so a tenant's storage usage is a fact.
//!
//! `files` was created by the PMS-128 split and never written to. Its only
//! reader is the `SUM(file_size)` behind `TenantUsage.storage_bytes`, so that
//! figure has always been a constant zero on every deployment, however much a
//! tenant uploaded. This is the writer it never had.
//!
//! It sits beside [`crate::storage::ObjectStore`] rather than inside it,
//! because the store moves bytes and knows nothing about a database. What binds
//! them is the key: the ledger records `ObjectKey::relative_path`, so the row
//! says where the object is in the store's own terms and neither has to know
//! the other's configuration.
//!
//! ## The duplication, stated
//!
//! `ticket_attachments.file_size` and `kb_article_attachments.file_size` still
//! exist and are still what each feature's API returns. So a size lives in two
//! places, which is the shape that drifts. It is accepted here for one release
//! rather than hidden: removing the feature columns means every read of an
//! attachment gains a join, and this issue is about a number that is wrong now.
//! The ledger is the source of truth for anything that spans features - the
//! tenant rollup today, retention and quotas later - and a feature column is
//! the source of truth for that feature's own response.

use uuid::Uuid;

use crate::db::Database;
use crate::storage::ObjectKey;
use crate::utils::error::AppResult;

/// What a stored file was, beside where it went.
pub struct FileRecord<'a> {
    /// The name the uploader gave it, which is not the name it is stored under.
    pub original_name: &'a str,
    pub mime_type: &'a str,
    pub file_size: i64,
    /// The `users` row behind the upload, when there is one. `None` for a
    /// portal upload (the actor is a `contacts` row) and for inbound email
    /// (there is no actor), which is why migration 126 drops the NOT NULL.
    pub uploaded_by_id: Option<Uuid>,
    /// What the file belongs to: `ticket_attachment`, `kb_attachment`,
    /// `tenant_logo`. Free text on purpose, matching the column, so a new kind
    /// of upload needs no migration to be recorded.
    pub entity_type: &'a str,
    pub entity_id: Option<Uuid>,
}

#[derive(Clone)]
pub struct FileLedger {
    db: Database,
}

// `Database` is not `Debug` (it wraps pools), and `TenantLogoStore` derives it.
// Printing "the ledger is present" is all a debug line can usefully say here.
impl std::fmt::Debug for FileLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileLedger")
    }
}

impl FileLedger {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Record a stored object, replacing any row for the same id.
    ///
    /// Upsert rather than insert, because a tenant logo is written to the same
    /// key every time it is replaced: one object, one row, whose size follows
    /// the bytes actually on disk. For an attachment, whose id is fresh per
    /// upload, the conflict arm never fires.
    ///
    /// The row id IS the object id where there is one, so a feature that knows
    /// its attachment id can find the ledger row without a second lookup, and a
    /// double-write cannot produce two rows for one file.
    pub async fn record(
        &self,
        tenant_id: Uuid,
        key: &ObjectKey,
        id: Uuid,
        file: FileRecord<'_>,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::record_in_tx(&mut tx, tenant_id, key, id, file).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The same write, in a transaction the caller owns (PMS-959).
    ///
    /// The invoice document is stored inside the transaction that sends the
    /// invoice, so its ledger row belongs there too: a row written from a
    /// second connection would survive a rollback of the send and would claim
    /// storage for a document that was never issued. It also avoids taking a
    /// second pool connection while one is already held, which is a deadlock
    /// waiting for a busy pool.
    pub async fn record_in_tx(
        tx: &mut crate::db::TenantTransaction<'_>,
        tenant_id: Uuid,
        key: &ObjectKey,
        id: Uuid,
        file: FileRecord<'_>,
    ) -> AppResult<()> {
        let path = key.relative_path()?.to_string_lossy().to_string();
        sqlx::query(
            r#"
            INSERT INTO files (
                id, tenant_id, original_name, storage_path, mime_type,
                file_size, uploaded_by_id, entity_type, entity_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO UPDATE SET
                original_name = EXCLUDED.original_name,
                storage_path  = EXCLUDED.storage_path,
                mime_type     = EXCLUDED.mime_type,
                file_size     = EXCLUDED.file_size
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(file.original_name)
        .bind(&path)
        .bind(file.mime_type)
        .bind(file.file_size)
        .bind(file.uploaded_by_id)
        .bind(file.entity_type)
        .bind(file.entity_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Forget a file that is no longer stored.
    ///
    /// Best effort, like the blob removal it accompanies: the feature's own row
    /// is already gone by the time this runs, and a ledger row for a file that
    /// no longer exists overstates a tenant's usage rather than breaking
    /// anything. Failing the request over it would turn a successful delete
    /// into an error.
    pub async fn forget(&self, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query("DELETE FROM files WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
