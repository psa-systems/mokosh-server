//! PMS-960: move every KB attachment under its tenant, once.
//!
//! Before PMS-960 a KB attachment was stored at the flat `kb-articles/{id}`,
//! with no tenant anywhere in the path. The layout is now
//! `{tenant}/kb-articles/{id}` like every other stored object, which leaves the
//! files already on a customer's volume in the wrong place. This is what walks
//! them over.
//!
//! ## Why a scheduled job rather than a boot step
//!
//! [`Scheduler`](crate::scheduler::Scheduler) fires every registered job once
//! immediately at startup and then on its interval, so registering this at an
//! hour gets the one-shot behaviour with no maintenance window AND makes a
//! transient failure self-healing instead of waiting for the next restart.
//! Blocking the boot on a filesystem walk of unknown size is the thing worth
//! avoiding; nothing about the API needs the move to have finished, because the
//! read path falls back to the old location until it has.
//!
//! ## Why the ledger drives it
//!
//! PMS-957 gave `files` a row per stored object holding the path below the
//! storage root, so "what is still at the old location" is a query rather than
//! a directory walk, and once the move is done it is a query that returns
//! nothing. A row with no ledger entry is selected too, because the ledger's
//! completeness is a property of PMS-957's backfill rather than something this
//! job should assume.
//!
//! ## What it does about failure
//!
//! The rename is atomic (see [`ObjectStore::rename`]), and the ledger update
//! follows it, so the two orders of partial failure are: a file that did not
//! move, which the read fallback still serves and the next tick retries; and a
//! file that moved with a ledger row still naming the old path, which the next
//! tick corrects because the file is already where it belongs.
//!
//! An attachment whose file is at NEITHER path is left completely alone. Its
//! ledger row keeps pointing at the old location, which is honest: rewriting it
//! to the new one would make a row that names a file nobody has look like a
//! successfully migrated object, and the cost of leaving it is two `stat` calls
//! an hour.

use async_trait::async_trait;
use uuid::Uuid;

use crate::db::Database;
use crate::scheduler::Job;
use crate::storage::{LocalStore, ObjectKey, ObjectStore};
use crate::utils::error::AppResult;

/// What one tick did, for the log line and for tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MoveOutcome {
    /// Files carried from the flat path to the tenant one.
    pub moved: usize,
    /// Already at the tenant path; only the ledger row needed correcting.
    pub already_moved: usize,
    /// Nothing on disk at either path, so nothing was touched.
    pub missing: usize,
}

impl MoveOutcome {
    fn considered(&self) -> usize {
        self.moved + self.already_moved + self.missing
    }
}

/// Walks pre-PMS-960 KB attachments to their tenant-scoped location.
#[derive(Clone)]
pub struct KbAttachmentMover {
    db: Database,
    store: LocalStore,
}

impl KbAttachmentMover {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            store: LocalStore::from_env(),
        }
    }

    /// One pass over everything still at the old location.
    ///
    /// No batch cap. The rows returned are only the unmoved ones, so the set
    /// shrinks to nothing after the first pass and a cap would buy nothing
    /// except leaving the remainder on the read fallback for another hour. A
    /// rename is a metadata operation, and a KB image is an illustration in an
    /// article rather than a bulk upload channel.
    pub async fn run_tick(&self) -> AppResult<MoveOutcome> {
        // SAFETY (PMS-285): this runs on the BYPASSRLS migrator pool because it
        // is a cross-tenant sweep with no `app.current_tenant` to set - the
        // same shape as the calendar, SLA and billing workers. It reads ids and
        // tenant ids only, and every write below re-derives its tenant from the
        // row it just read.
        let pending: Vec<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT ka.id, ka.tenant_id
            FROM kb_article_attachments ka
            LEFT JOIN files f ON f.id = ka.id
            WHERE f.id IS NULL OR f.storage_path LIKE 'kb-articles/%'
            ORDER BY ka.created_at
            "#,
        )
        .fetch_all(self.db.migrator_pool())
        .await?;

        let mut outcome = MoveOutcome::default();
        for (id, tenant_id) in pending {
            let destination = ObjectKey::kb_attachment(tenant_id, id);
            let legacy = ObjectKey::legacy_kb_attachment(tenant_id, id);

            if self.store.exists(&destination).await? {
                // A fresh upload, or a tick that moved the file and then failed
                // before it could say so.
                outcome.already_moved += 1;
            } else if self.store.exists(&legacy).await? {
                self.store.rename(&legacy, &destination).await?;
                outcome.moved += 1;
            } else {
                outcome.missing += 1;
                continue;
            }

            // The ledger follows the file, never the other way round. A row
            // that names a path before the bytes are there is the one ordering
            // that can lie.
            self.record_moved(tenant_id, id, &destination).await?;
        }

        if outcome.considered() > 0 {
            tracing::info!(
                moved = outcome.moved,
                already_moved = outcome.already_moved,
                missing = outcome.missing,
                "kb_attachment_move: pass complete"
            );
        }
        Ok(outcome)
    }

    /// Point the ledger row at where the file now is.
    ///
    /// Tenant-scoped, unlike the sweep above: the tenant is known by this point
    /// so there is no reason to write through the privileged pool. An
    /// attachment with no ledger row updates nothing and is left to PMS-957's
    /// own writers; this job exists to move files, not to backfill a ledger.
    async fn record_moved(&self, tenant_id: Uuid, id: Uuid, key: &ObjectKey) -> AppResult<()> {
        let path = key.relative_path()?.to_string_lossy().to_string();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query("UPDATE files SET storage_path = $1 WHERE tenant_id = $2 AND id = $3")
            .bind(&path)
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl Job for KbAttachmentMover {
    fn name(&self) -> &'static str {
        "kb_attachment_move"
    }

    async fn run(&self) -> AppResult<()> {
        self.run_tick().await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The query's `LIKE` pattern has to match what the ledger actually holds,
    /// which is `ObjectKey::relative_path` for the legacy key and nothing else.
    ///
    /// A pattern that misses would make this job a no-op that reports success
    /// forever, which is the failure mode worth a test: nothing errors, nothing
    /// moves, and every read quietly stays on the fallback.
    #[test]
    fn the_pending_query_matches_the_path_the_ledger_stores() {
        let legacy = ObjectKey::legacy_kb_attachment(Uuid::new_v4(), Uuid::new_v4());
        let stored = legacy
            .relative_path()
            .expect("a legacy key has a path")
            .to_string_lossy()
            .to_string();
        assert!(
            stored.starts_with("kb-articles/"),
            "the sweep selects on this prefix; {stored:?} would never be found"
        );
        // And the destination must NOT match it, or a moved file is selected
        // again on every tick.
        let moved = ObjectKey::kb_attachment(Uuid::new_v4(), Uuid::new_v4())
            .relative_path()
            .expect("path")
            .to_string_lossy()
            .to_string();
        assert!(!moved.starts_with("kb-articles/"));
    }
}
