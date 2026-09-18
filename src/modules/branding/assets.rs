//! MAPPS-618/622 (mokosh-branding prompt 002): parameterized asset
//! store for branding uploads at both tenant + Company scope. Handles
//! the three asset kinds (logo, favicon, background) uniformly per
//! scope.
//!
//! Storage layout under `$ATTACHMENT_DIR`:
//!
//! ```text
//! attachments/
//!   tenant-favicons/{tenant_id}.{ext}
//!   tenant-backgrounds/{tenant_id}.{ext}
//!   company-logos/{company_id}.{ext}
//!   company-favicons/{company_id}.{ext}
//!   company-backgrounds/{company_id}.{ext}
//! ```
//!
//! The tenant logo write (`AssetScope::Tenant` + `BrandAssetKind::Logo`)
//! converges on the same object key `src/modules/tenants/logo.rs` writes
//! (PMS-1234): both entry points call through `ObjectKey::tenant_logo` and
//! record the same `FileLedger` row, so a logo uploaded from either route is
//! the same object. This module owns the on-disk layout for the two new
//! tenant kinds (favicon + background) plus every Company kind, none of
//! which have an `ObjectKind` of their own yet.
//!
//! Same MIME allowlist as the tenant logo (`image/png|jpeg|webp|gif`);
//! SVG stays refused. Per-kind size caps default to sensible values
//! and can be tuned per deployment via env.

use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;

use crate::config::{self, registry as keys, ConfigKey};
use crate::db::Database;
use crate::storage::{FileLedger, FileRecord, ObjectKey, ObjectProvider};
use crate::utils::error::{AppError, AppResult};
use crate::utils::upload_limits::oversized_upload_error;

const ALLOWED_MIME: &[(&str, &str)] = &[
    ("image/png", "png"),
    ("image/jpeg", "jpg"),
    ("image/webp", "webp"),
    ("image/gif", "gif"),
];

const DEFAULT_LOGO_MAX_BYTES: u64 = 1024 * 1024; // 1 MiB
const DEFAULT_FAVICON_MAX_BYTES: u64 = 512 * 1024; // 512 KiB
const DEFAULT_BACKGROUND_MAX_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

/// The three brand asset kinds. Each maps to a distinct subdirectory
/// per scope + its own size cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrandAssetKind {
    Logo,
    Favicon,
    Background,
}

/// Type alias kept during the phase-B rollout so existing callers
/// still compile; new code uses [`BrandAssetKind`] directly.
pub type CompanyAssetKind = BrandAssetKind;

/// Which scope an asset belongs to. Tenant scope maps to the MSP-
/// level defaults every Company inherits; Company scope maps to the
/// per-Company override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetScope {
    Tenant(Uuid),
    Company(Uuid),
}

impl AssetScope {
    fn subdir_prefix(self) -> &'static str {
        match self {
            Self::Tenant(_) => "tenant",
            Self::Company(_) => "company",
        }
    }

    fn id(self) -> Uuid {
        match self {
            Self::Tenant(id) | Self::Company(id) => id,
        }
    }
}

impl BrandAssetKind {
    fn kind_dir(self) -> &'static str {
        match self {
            Self::Logo => "logos",
            Self::Favicon => "favicons",
            Self::Background => "backgrounds",
        }
    }

    /// The cap's configuration key. A closed match over the six
    /// `(scope, kind)` pairs, so all six are declarable in the registry
    /// (PMS-982) even though the read site names none of them: this is exactly
    /// the computed-key read that a literal-only scan of `.env.example`
    /// parity could not see, and five of the six were reachable from nowhere.
    fn config_key(self, scope: AssetScope) -> &'static ConfigKey {
        match (scope, self) {
            (AssetScope::Tenant(_), Self::Logo) => &keys::TENANT_LOGO_MAX_BYTES,
            (AssetScope::Tenant(_), Self::Favicon) => &keys::BRANDING_TENANT_FAVICON_MAX_BYTES,
            (AssetScope::Tenant(_), Self::Background) => {
                &keys::BRANDING_TENANT_BACKGROUND_MAX_BYTES
            }
            (AssetScope::Company(_), Self::Logo) => &keys::BRANDING_COMPANY_LOGO_MAX_BYTES,
            (AssetScope::Company(_), Self::Favicon) => &keys::BRANDING_COMPANY_FAVICON_MAX_BYTES,
            (AssetScope::Company(_), Self::Background) => {
                &keys::BRANDING_COMPANY_BACKGROUND_MAX_BYTES
            }
        }
    }

    fn default_max_bytes(self) -> u64 {
        match self {
            Self::Logo => DEFAULT_LOGO_MAX_BYTES,
            Self::Favicon => DEFAULT_FAVICON_MAX_BYTES,
            Self::Background => DEFAULT_BACKGROUND_MAX_BYTES,
        }
    }

    /// Parse a URL segment (`"logo"`, `"favicon"`, `"background"`) into
    /// a kind. Returns `None` for anything else so the route falls
    /// through to 404 rather than a validation error.
    pub fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "logo" => Some(Self::Logo),
            "favicon" => Some(Self::Favicon),
            "background" => Some(Self::Background),
            _ => None,
        }
    }

    /// The JSON key the SPA reads for the asset's URL. Matches the
    /// `EffectiveBranding` field names 1:1.
    pub fn url_field(self) -> &'static str {
        match self {
            Self::Logo => "logo_url",
            Self::Favicon => "favicon_url",
            Self::Background => "background_url",
        }
    }

    /// The JSON key the SPA reads for the asset's stored MIME.
    pub fn mime_field(self) -> &'static str {
        match self {
            Self::Logo => "logo_mime",
            Self::Favicon => "favicon_mime",
            Self::Background => "background_mime",
        }
    }
}

fn extension_for(mime: &str) -> &'static str {
    ALLOWED_MIME
        .iter()
        .find(|(m, _)| *m == mime)
        .map(|(_, ext)| *ext)
        .unwrap_or("bin")
}

/// Validate + normalize a content-type header. Same shape as the
/// tenant logo module's `check_mime`; duplicated here so this module
/// stays independent of any tenant-logo refactor.
pub fn check_mime(raw: &str) -> AppResult<&'static str> {
    let base = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    ALLOWED_MIME
        .iter()
        .find(|(m, _)| *m == base)
        .map(|(m, _)| *m)
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "Unsupported image type `{base}`. Use PNG, JPEG, WebP or GIF."
            ))
        })
}

#[derive(Clone, Debug)]
pub struct BrandingAssetStore {
    root: PathBuf,
    /// PMS-1234: where the tenant logo (only) actually goes. `ObjectKey` has
    /// no variant for the other five (scope, kind) pairs yet, so they stay on
    /// the `root`-relative layout below; this field exists solely to give the
    /// tenant logo the same writer `TenantLogoStore` uses.
    logo_store: Arc<dyn ObjectProvider>,
    /// PMS-1234, PMS-957: one row per stored tenant logo, the same ledger
    /// `TenantLogoStore::with_ledger` writes. `None` for the public read
    /// router, which has no database and only ever reads.
    ledger: Option<FileLedger>,
}

/// Type alias kept during the phase-B rollout so existing callers
/// still compile; new code uses [`BrandingAssetStore`] directly.
pub type CompanyAssetStore = BrandingAssetStore;

impl BrandingAssetStore {
    pub fn from_env() -> Self {
        let root = config::get(&keys::ATTACHMENT_DIR)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./attachments"));
        Self {
            root,
            logo_store: crate::storage::shared(),
            ledger: None,
        }
    }

    /// PMS-1234: give this store a database to record tenant-logo uploads in.
    /// Mirrors `TenantLogoStore::with_ledger`.
    pub fn with_ledger(mut self, db: Database) -> Self {
        self.ledger = Some(FileLedger::new(db));
        self
    }

    /// The tenant this (scope, kind) pair addresses through `ObjectKey`, or
    /// `None` for the five pairs still on the local-path layout below.
    fn tenant_logo_id(scope: AssetScope, kind: BrandAssetKind) -> Option<Uuid> {
        match (scope, kind) {
            (AssetScope::Tenant(id), BrandAssetKind::Logo) => Some(id),
            _ => None,
        }
    }

    pub fn max_bytes(&self, kind: BrandAssetKind, scope: AssetScope) -> u64 {
        config::get(kind.config_key(scope))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| kind.default_max_bytes())
    }

    /// The largest cap across every [`BrandAssetKind`] for a scope VARIANT
    /// (the id inside `scope` is not read; `Uuid::nil()` is fine). One route
    /// accepts all three kinds through the `{asset}` path segment and only
    /// resolves which cap applies inside `store`, after axum has already
    /// buffered the body, so the route's `DefaultBodyLimit` (PMS-1233) has to
    /// cover whichever of the three this request turns out to name.
    pub fn max_bytes_for_scope(&self, scope: AssetScope) -> u64 {
        [
            BrandAssetKind::Logo,
            BrandAssetKind::Favicon,
            BrandAssetKind::Background,
        ]
        .into_iter()
        .map(|kind| self.max_bytes(kind, scope))
        .max()
        .unwrap_or(0)
    }

    fn dir_for(&self, scope: AssetScope, kind: BrandAssetKind) -> PathBuf {
        self.root
            .join(format!("{}-{}", scope.subdir_prefix(), kind.kind_dir()))
    }

    fn path_for(&self, scope: AssetScope, kind: BrandAssetKind, mime: &str) -> PathBuf {
        self.dir_for(scope, kind)
            .join(format!("{}.{}", scope.id(), extension_for(mime)))
    }

    /// Store the asset, overwriting whatever this (scope, kind) pair
    /// had. Returns the normalized MIME the caller records in the
    /// branding JSONB.
    pub async fn store(
        &self,
        scope: AssetScope,
        kind: BrandAssetKind,
        mime: &str,
        bytes: &[u8],
    ) -> AppResult<&'static str> {
        let mime = check_mime(mime)?;
        if bytes.is_empty() {
            return Err(AppError::BadRequest("The uploaded file is empty.".into()));
        }
        let cap = self.max_bytes(kind, scope);
        if bytes.len() as u64 > cap {
            return Err(oversized_upload_error("image", cap));
        }
        self.remove(scope, kind).await;

        if let Some(tenant_id) = Self::tenant_logo_id(scope, kind) {
            let key = ObjectKey::tenant_logo(tenant_id, extension_for(mime));
            self.logo_store.put(&key, bytes).await?;
            if let Some(ledger) = &self.ledger {
                // Keyed on the TENANT, not a fresh id: one logo per tenant,
                // upserted the way `TenantLogoStore::store` does.
                ledger
                    .record(
                        tenant_id,
                        &key,
                        tenant_id,
                        FileRecord {
                            original_name: "logo",
                            mime_type: mime,
                            file_size: bytes.len() as i64,
                            uploaded_by_id: None,
                            entity_type: "tenant_logo",
                            entity_id: Some(tenant_id),
                        },
                    )
                    .await?;
            }
            return Ok(mime);
        }

        tokio::fs::create_dir_all(self.dir_for(scope, kind))
            .await
            .map_err(|e| AppError::Internal(format!("create asset dir: {e}")))?;
        tokio::fs::write(self.path_for(scope, kind, mime), bytes)
            .await
            .map_err(|e| AppError::Internal(format!("write asset: {e}")))?;
        Ok(mime)
    }

    pub async fn read(
        &self,
        scope: AssetScope,
        kind: BrandAssetKind,
        mime: &str,
    ) -> AppResult<Vec<u8>> {
        let mime = check_mime(mime)?;

        if let Some(tenant_id) = Self::tenant_logo_id(scope, kind) {
            let extension = extension_for(mime);
            if let Ok(bytes) = self
                .logo_store
                .read(&ObjectKey::tenant_logo(tenant_id, extension))
                .await
            {
                return Ok(bytes);
            }
            // Same pre-move fallback `TenantLogoStore::read` falls back to: a
            // logo written before this converged is still at the shared
            // `tenant-logos/{tenant}.{ext}` layout until `TenantLogoMover`
            // reaches it.
            return self
                .logo_store
                .read(&ObjectKey::legacy_tenant_logo(tenant_id, extension))
                .await
                .map_err(|_| AppError::NotFound("Asset".to_string()));
        }

        tokio::fs::read(self.path_for(scope, kind, mime))
            .await
            .map_err(|_| AppError::NotFound("Asset".to_string()))
    }

    /// Remove every stored format for a (scope, kind) pair. Best-
    /// effort: an unreachable file the branding row no longer points
    /// at cannot fail the request that cleared the row.
    pub async fn remove(&self, scope: AssetScope, kind: BrandAssetKind) {
        if let Some(tenant_id) = Self::tenant_logo_id(scope, kind) {
            for (_, extension) in ALLOWED_MIME {
                let _ = self
                    .logo_store
                    .delete(&ObjectKey::tenant_logo(tenant_id, *extension))
                    .await;
                let _ = self
                    .logo_store
                    .delete(&ObjectKey::legacy_tenant_logo(tenant_id, *extension))
                    .await;
            }
            return;
        }

        for (mime, _) in ALLOWED_MIME {
            let _ = tokio::fs::remove_file(self.path_for(scope, kind, mime)).await;
        }
    }
}

/// Public-URL path a client fetches this asset from. Relative on
/// purpose: SPA joins with `API_BASE`; the email composer joins with
/// the configured public base.
pub fn asset_path(scope: AssetScope, kind: BrandAssetKind) -> String {
    let segment = match kind {
        BrandAssetKind::Logo => "logo",
        BrandAssetKind::Favicon => "favicon",
        BrandAssetKind::Background => "background",
    };
    match scope {
        AssetScope::Tenant(id) => format!("/api/v1/public/tenants/{id}/{segment}"),
        AssetScope::Company(id) => format!("/api/v1/public/companies/{id}/{segment}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_maps_to_kind() {
        assert_eq!(
            CompanyAssetKind::from_segment("logo"),
            Some(CompanyAssetKind::Logo)
        );
        assert_eq!(
            CompanyAssetKind::from_segment("favicon"),
            Some(CompanyAssetKind::Favicon)
        );
        assert_eq!(
            CompanyAssetKind::from_segment("background"),
            Some(CompanyAssetKind::Background)
        );
        assert_eq!(CompanyAssetKind::from_segment("banner"), None);
    }

    #[test]
    fn svg_is_refused_here_too() {
        assert!(check_mime("image/svg+xml").is_err());
        assert!(check_mime("application/octet-stream").is_err());
    }

    #[test]
    fn asset_path_stays_relative() {
        let id = Uuid::nil();
        let p = asset_path(AssetScope::Company(id), BrandAssetKind::Logo);
        assert!(p.starts_with("/api/v1/public/companies/"));
        assert!(p.ends_with("/logo"));
    }

    #[test]
    fn tenant_asset_path_shape() {
        let id = Uuid::nil();
        let p = asset_path(AssetScope::Tenant(id), BrandAssetKind::Favicon);
        assert!(p.starts_with("/api/v1/public/tenants/"));
        assert!(p.ends_with("/favicon"));
    }
}
