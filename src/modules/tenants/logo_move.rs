//! Move every tenant logo under its own tenant directory, once.
//!
//! The live logo was stored at `tenant-logos/{tenant}.{ext}`: a shared
//! directory with the tenant in the FILENAME. It was the last kind still shaped
//! that way, after PMS-960 moved KB attachments out of exactly that shape. The
//! layout is now `{tenant}/logo.{ext}` like every other stored object, which
//! leaves the files already on a customer's volume in the wrong place. This is
//! what walks them over.
//!
//! It is the PMS-960 mover with one difference, and the difference is what the
//! comments below are about: a KB attachment has a row of its own to sweep, and
//! a logo does not. There is no `tenant_logos` table. What says a tenant has a
//! logo is `tenants.branding->>'logo_mime'`, and the extension the file is
//! stored under is derived from that mime, so the sweep reads branding and the
//! extension comes back through the same `extension_for` the upload used. A
//! tenant whose branding names no mime has no logo to move, however many stray
//! files might sit under the old directory: this job moves what the product
//! considers a logo, and an orphan is not one.
//!
//! ## Why a scheduled job rather than a boot step
//!
//! [`Scheduler`](crate::scheduler::Scheduler) fires every registered job once
//! immediately at startup and then on its interval, so registering this at an
//! hour gets the one-shot behaviour with no maintenance window AND makes a
//! transient failure self-healing instead of waiting for the next restart.
//! Nothing about the API needs the move to have finished, because
//! `TenantLogoStore::read` falls back to the old location until it has.
//!
//! ## What it does about failure
//!
//! The rename is atomic (see [`ObjectProvider::rename`]), and the ledger update
//! follows it, so the two orders of partial failure are: a file that did not
//! move, which the read fallback still serves and the next tick retries; and a
//! file that moved with a ledger row still naming the old path, which the next
//! tick corrects because the file is already where it belongs.
//!
//! A tenant whose logo is at NEITHER path is left completely alone. Its ledger
//! row, if it has one, keeps pointing at the old location, which is honest:
//! rewriting it to the new one would make a row that names a file nobody has
//! look like a successfully migrated object.

use async_trait::async_trait;
use uuid::Uuid;

use std::sync::Arc;

use crate::db::Database;
use crate::scheduler::Job;
use crate::storage::{ObjectKey, ObjectProvider};
use crate::utils::error::AppResult;

use super::logo::extension_for_mime;

/// What one tick did, for the log line and for tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LogoMoveOutcome {
    /// Files carried from the shared directory to the tenant one.
    pub moved: usize,
    /// Already at the tenant path; only the ledger row needed correcting.
    pub already_moved: usize,
    /// Nothing on disk at either path, so nothing was touched.
    pub missing: usize,
}

impl LogoMoveOutcome {
    fn considered(&self) -> usize {
        self.moved + self.already_moved + self.missing
    }
}

/// Walks pre-move tenant logos to their tenant-scoped location.
#[derive(Clone)]
pub struct TenantLogoMover {
    db: Database,
    store: Arc<dyn ObjectProvider>,
}

impl TenantLogoMover {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            store: crate::storage::shared(),
        }
    }

    /// One pass over every tenant whose logo may still be at the old location.
    ///
    /// No batch cap, for the PMS-960 reason and one stronger: there is at most
    /// one logo per tenant, so the whole set is bounded by the tenant count and
    /// a rename is a metadata operation.
    pub async fn run_tick(&self) -> AppResult<LogoMoveOutcome> {
        // SAFETY (PMS-285): this runs on the BYPASSRLS migrator pool because it
        // is a cross-tenant sweep with no `app.current_tenant` to set - the
        // same shape as the KB attachment mover and the calendar, SLA and
        // billing workers. It reads tenant ids and a branding mime only, and
        // every write below re-derives its tenant from the row it just read.
        //
        // The ledger join is a LEFT JOIN and the `f.id IS NULL` arm is not
        // optional: a logo uploaded before PMS-957 gave `files` a writer has no
        // row at all, and a sweep that only looked at ledger rows would leave
        // exactly the oldest logos behind.
        let pending: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT t.id, t.branding ->> 'logo_mime'
            FROM tenants t
            LEFT JOIN files f ON f.id = t.id AND f.entity_type = 'tenant_logo'
            WHERE t.branding ->> 'logo_mime' IS NOT NULL
              AND (f.id IS NULL OR f.storage_path LIKE 'tenant-logos/%')
            ORDER BY t.created_at
            "#,
        )
        .fetch_all(self.db.migrator_pool())
        .await?;

        let mut outcome = LogoMoveOutcome::default();
        for (tenant_id, mime) in pending {
            let extension = extension_for_mime(&mime);
            let destination = ObjectKey::tenant_logo(tenant_id, extension);
            let legacy = ObjectKey::legacy_tenant_logo(tenant_id, extension);

            if self.store.exists(&destination).await? {
                // A logo replaced since the deploy, or a tick that moved the
                // file and then failed before it could say so.
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
            self.record_moved(tenant_id, &destination).await?;
        }

        if outcome.considered() > 0 {
            tracing::info!(
                moved = outcome.moved,
                already_moved = outcome.already_moved,
                missing = outcome.missing,
                "tenant_logo_move: pass complete"
            );
        }
        Ok(outcome)
    }

    /// Point the ledger row at where the file now is.
    ///
    /// Tenant-scoped, unlike the sweep above: the tenant is known by this point
    /// so there is no reason to write through the privileged pool. The row id
    /// IS the tenant id for a logo (`TenantLogoStore::store` says why: one
    /// object per tenant, upserted, so replacing a logo does not add a second
    /// row to the usage rollup). A tenant with no ledger row updates nothing
    /// and is left to PMS-957's own writers; this job exists to move files, not
    /// to backfill a ledger.
    async fn record_moved(&self, tenant_id: Uuid, key: &ObjectKey) -> AppResult<()> {
        let path = key.relative_path()?.to_string_lossy().to_string();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE files SET storage_path = $1 \
             WHERE tenant_id = $2 AND id = $3 AND entity_type = 'tenant_logo'",
        )
        .bind(&path)
        .bind(tenant_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl Job for TenantLogoMover {
    fn name(&self) -> &'static str {
        "tenant_logo_move"
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
        let tenant = Uuid::new_v4();
        let stored = ObjectKey::legacy_tenant_logo(tenant, "png")
            .relative_path()
            .expect("a legacy key has a path")
            .to_string_lossy()
            .to_string();
        assert!(
            stored.starts_with("tenant-logos/"),
            "the sweep selects on this prefix; {stored:?} would never be found"
        );
        // And the destination must NOT match it, or a moved logo is selected
        // again on every tick.
        let moved = ObjectKey::tenant_logo(tenant, "png")
            .relative_path()
            .expect("path")
            .to_string_lossy()
            .to_string();
        assert!(!moved.starts_with("tenant-logos/"));
    }

    /// The sweep reads a mime out of branding and the file is stored under an
    /// extension, so the two have to be joined by the same function the upload
    /// used. Deriving the extension any other way here is how a mover looks for
    /// `image/png` and misses `{tenant}.png`.
    #[test]
    fn the_extension_comes_from_the_same_place_the_upload_got_it() {
        assert_eq!(extension_for_mime("image/png"), "png");
        assert_eq!(extension_for_mime("image/jpeg"), "jpg");
        assert_eq!(extension_for_mime("image/webp"), "webp");
        assert_eq!(extension_for_mime("image/gif"), "gif");
        // A branding row can hold whatever an older release let through; the
        // key still has to be constructible so the tick reports `missing`
        // rather than erroring the whole pass.
        assert_eq!(extension_for_mime("application/x-thing"), "bin");
    }
}
