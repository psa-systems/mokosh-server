//! PMS-1397 one-shot: walk the five legacy branding directories and
//! move every file under its tenant.
//!
//! The pre-PMS-1397 layout stored five (scope, kind) pairs in
//! directories shared across tenants:
//!
//! - `tenant-favicons/{tenant_id}.{ext}`
//! - `tenant-backgrounds/{tenant_id}.{ext}`
//! - `company-logos/{company_id}.{ext}`
//! - `company-favicons/{company_id}.{ext}`
//! - `company-backgrounds/{company_id}.{ext}`
//!
//! The new layout is tenant-first:
//!
//! - `{tenant}/branding/favicon.{ext}`
//! - `{tenant}/branding/background.{ext}`
//! - `{tenant}/branding/company-{kind}/{company_id}.{ext}`
//!
//! For tenant-scoped files the tenant is the filename stem. For
//! company-scoped files it comes from the `companies` row (which the
//! owning JSONB already pins the file to). A file whose company no
//! longer exists is left in place and logged: deleting it would hide
//! an orphan that may still need investigation.
//!
//! File-first-then-ledger (PMS-1320): write the new location, then
//! remove the old; a crash between leaves two readable copies, which
//! `BrandingAssetStore` tolerates via its legacy fallback.

use std::path::{Path, PathBuf};

use sqlx::Row;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};

/// Entry point for the one-shot pass. Walks the five legacy
/// directories under `root` and moves each file.
pub async fn move_all(root: PathBuf, db: Database) -> AppResult<()> {
    let plan = [
        ("tenant-favicons", AssetKindDir::TenantFavicon),
        ("tenant-backgrounds", AssetKindDir::TenantBackground),
        ("company-logos", AssetKindDir::CompanyLogo),
        ("company-favicons", AssetKindDir::CompanyFavicon),
        ("company-backgrounds", AssetKindDir::CompanyBackground),
    ];
    let mut moved = 0usize;
    let mut skipped = 0usize;
    for (legacy_dir, variant) in plan {
        let dir = root.join(legacy_dir);
        if !tokio::fs::try_exists(&dir).await.unwrap_or(false) {
            continue;
        }
        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .map_err(|e| AppError::Internal(format!("read_dir {dir:?}: {e}")))?;
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| AppError::Internal(format!("read_dir entry: {e}")))?
        {
            let path = entry.path();
            let Some(outcome) = move_one(&root, &path, variant, &db).await? else {
                continue;
            };
            match outcome {
                MoveOutcome::Moved => moved += 1,
                MoveOutcome::Skipped => skipped += 1,
            }
        }
    }
    tracing::info!(moved, skipped, "PMS-1397 branding mover complete");
    Ok(())
}

#[derive(Clone, Copy)]
enum AssetKindDir {
    TenantFavicon,
    TenantBackground,
    CompanyLogo,
    CompanyFavicon,
    CompanyBackground,
}

impl AssetKindDir {
    fn tenant_stem(self) -> Option<&'static str> {
        match self {
            Self::TenantFavicon => Some("favicon"),
            Self::TenantBackground => Some("background"),
            _ => None,
        }
    }

    fn company_subdir(self) -> Option<&'static str> {
        match self {
            Self::CompanyLogo => Some("company-logos"),
            Self::CompanyFavicon => Some("company-favicons"),
            Self::CompanyBackground => Some("company-backgrounds"),
            _ => None,
        }
    }
}

enum MoveOutcome {
    Moved,
    Skipped,
}

async fn move_one(
    root: &Path,
    legacy_path: &Path,
    variant: AssetKindDir,
    db: &Database,
) -> AppResult<Option<MoveOutcome>> {
    let Some(file_name) = legacy_path.file_name().and_then(|f| f.to_str()) else {
        return Ok(None);
    };
    let (stem, ext) = match file_name.rsplit_once('.') {
        Some((s, e)) => (s, e),
        None => return Ok(None),
    };
    let Ok(id) = Uuid::parse_str(stem) else {
        // Not a UUID-named file. Leave it in place.
        tracing::warn!(path = %legacy_path.display(), "PMS-1397 mover: non-UUID filename, skipping");
        return Ok(Some(MoveOutcome::Skipped));
    };

    let new_path = match variant.tenant_stem() {
        Some(kind_stem) => {
            // Tenant-scoped: filename IS the tenant.
            root.join(id.to_string())
                .join("branding")
                .join(format!("{kind_stem}.{ext}"))
        }
        None => {
            // Company-scoped: resolve tenant from `companies`.
            let subdir = variant
                .company_subdir()
                .expect("company variant has subdir");
            // SAFETY (PMS-285): identity-plane lookup to resolve a stored
            // asset's owning tenant. One row, keyed by the company id in
            // the filename; no RLS on companies for this read because the
            // mover runs out-of-band at boot with no caller tenant GUC set.
            let row = sqlx::query("SELECT tenant_id FROM companies WHERE id = $1")
                .bind(id)
                .fetch_optional(db.pool())
                .await?;
            let Some(row) = row else {
                tracing::warn!(
                    company_id = %id,
                    path = %legacy_path.display(),
                    "PMS-1397 mover: orphan asset (company not found), leaving in place"
                );
                return Ok(Some(MoveOutcome::Skipped));
            };
            let tenant_id: Uuid = row
                .try_get("tenant_id")
                .map_err(|e| AppError::Internal(format!("tenant_id decode: {e}")))?;
            root.join(tenant_id.to_string())
                .join("branding")
                .join(subdir)
                .join(format!("{id}.{ext}"))
        }
    };

    if tokio::fs::try_exists(&new_path).await.unwrap_or(false) {
        // The new path already carries a file: a write landed since this
        // run started, or a previous mover pass moved it. Clear the
        // legacy source so the next read does not fall back onto it.
        if let Err(e) = tokio::fs::remove_file(legacy_path).await {
            tracing::warn!(path = %legacy_path.display(), error = %e, "PMS-1397 mover: legacy delete failed");
        }
        return Ok(Some(MoveOutcome::Skipped));
    }

    if let Some(parent) = new_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::Internal(format!("create_dir_all {parent:?}: {e}")))?;
    }
    // Copy-then-delete rather than rename: the dev stack's attachments
    // volume is one filesystem, but a cross-mount deployment would make
    // rename ENOEXDEV. Copy is universal; delete is best-effort.
    tokio::fs::copy(legacy_path, &new_path)
        .await
        .map_err(|e| AppError::Internal(format!("copy {legacy_path:?} -> {new_path:?}: {e}")))?;
    if let Err(e) = tokio::fs::remove_file(legacy_path).await {
        tracing::warn!(path = %legacy_path.display(), error = %e, "PMS-1397 mover: legacy delete after copy failed");
    }
    tracing::debug!(from = %legacy_path.display(), to = %new_path.display(), "PMS-1397 mover: moved");
    Ok(Some(MoveOutcome::Moved))
}

/// Register the one-shot pass at boot. Mirrors every other PMS-1320
/// one-shot (e.g. `TenantLogoMover` for the pre-PMS-1234 logo).
pub fn arm(root: PathBuf, db: Database) {
    crate::scheduler::one_shot::spawn_once("branding_mover_pms_1397", async move {
        move_all(root, db).await
    });
}
