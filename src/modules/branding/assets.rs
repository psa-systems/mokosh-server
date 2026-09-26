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
use crate::storage::{FileLedger, FileRecord, ObjectKey, ObjectProvider, ObjectReader};
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

/// What [`BrandingAssetStore::stat`] can tell a caller about the currently
/// stored asset without opening it.
pub struct AssetMeta {
    pub size: u64,
    pub etag: String,
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
    /// `TenantLogoStore::with_ledger` writes. PMS-1246: also read by
    /// `stat`, so the public read router now attaches one too; `None` is
    /// still valid wherever a caller only stores or removes and never
    /// serves the tenant-logo pair.
    ledger: Option<FileLedger>,
}

/// Type alias kept during the phase-B rollout so existing callers
/// still compile; new code uses [`BrandingAssetStore`] directly.
pub type CompanyAssetStore = BrandingAssetStore;

impl BrandingAssetStore {
    pub fn from_env() -> Self {
        // PMS-1317: the root comes from `crate::storage`, the provider of
        // record for it, rather than from a second read of the variable here.
        // That mattered the moment the variable was renamed: this reader would
        // have kept asking for `ATTACHMENT_DIR` while the provider moved to
        // `STORAGE_ROOT`, and a deployment setting only the new name would have
        // split its uploads across two roots inside one process - which is the
        // exact defect PMS-910 was filed for, reintroduced by the rename meant
        // to make the setting clearer.
        Self {
            root: crate::storage::StorageConfig::from_env().root,
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
        // PMS-1238: write the new file first and clear the other formats
        // after, so a failed write leaves the old asset in place.
        if let Some(tenant_id) = Self::tenant_logo_id(scope, kind) {
            let key = ObjectKey::tenant_logo(tenant_id, extension_for(mime));
            self.logo_store.put(&key, bytes).await?;
            self.remove_except(scope, kind, Some(mime)).await;
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
        self.remove_except(scope, kind, Some(mime)).await;
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

    /// Size and an ETag for the currently-stored asset, without reading its
    /// bytes. PMS-1246: the public read needs this BEFORE it opens the blob,
    /// so a matching `If-None-Match` never touches the file at all.
    ///
    /// Unlike a ticket or KB attachment, a branding asset is mutable in
    /// place: the same key is overwritten on every re-upload, so there is no
    /// fresh id to build a validator from. The size is what is cheaply
    /// available on both storage shapes here (a local `stat`, or the
    /// `files` ledger row PMS-1234 already writes for the tenant logo), so
    /// the ETag is a weak validator over it: two uploads that land on the
    /// exact same byte count within the asset's cache window are
    /// indistinguishable. That is an accepted tradeoff, not an oversight -
    /// closing it needs a stored digest this table does not carry yet.
    pub async fn stat(
        &self,
        scope: AssetScope,
        kind: BrandAssetKind,
        mime: &str,
    ) -> AppResult<AssetMeta> {
        let mime = check_mime(mime)?;

        if let Some(tenant_id) = Self::tenant_logo_id(scope, kind) {
            let Some(ledger) = &self.ledger else {
                return Err(AppError::NotFound("Asset".to_string()));
            };
            let size = ledger
                .latest_file_size(tenant_id, "tenant_logo")
                .await?
                .ok_or_else(|| AppError::NotFound("Asset".to_string()))?
                as u64;
            return Ok(AssetMeta {
                size,
                etag: format!("\"{tenant_id}-logo-{size}\""),
            });
        }

        let path = self.path_for(scope, kind, mime);
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|_| AppError::NotFound("Asset".to_string()))?;
        let size = meta.len();
        Ok(AssetMeta {
            size,
            etag: format!("\"{}-{}-{}\"", scope.id(), kind.kind_dir(), size),
        })
    }

    /// Stream the currently-stored asset's bytes.
    pub async fn open(
        &self,
        scope: AssetScope,
        kind: BrandAssetKind,
        mime: &str,
    ) -> AppResult<ObjectReader> {
        let mime = check_mime(mime)?;

        if let Some(tenant_id) = Self::tenant_logo_id(scope, kind) {
            let extension = extension_for(mime);
            if let Ok(reader) = self
                .logo_store
                .open(&ObjectKey::tenant_logo(tenant_id, extension))
                .await
            {
                return Ok(reader);
            }
            return self
                .logo_store
                .open(&ObjectKey::legacy_tenant_logo(tenant_id, extension))
                .await
                .map_err(|_| AppError::NotFound("Asset".to_string()));
        }

        let file = tokio::fs::File::open(self.path_for(scope, kind, mime))
            .await
            .map_err(|_| AppError::NotFound("Asset".to_string()))?;
        Ok(Box::pin(file))
    }

    /// Remove every stored format for a (scope, kind) pair. Best-
    /// effort: an unreachable file the branding row no longer points
    /// at cannot fail the request that cleared the row.
    pub async fn remove(&self, scope: AssetScope, kind: BrandAssetKind) {
        self.remove_except(scope, kind, None).await;
    }

    /// Remove every stored format except `keep_mime`, the one just written.
    async fn remove_except(
        &self,
        scope: AssetScope,
        kind: BrandAssetKind,
        keep_mime: Option<&str>,
    ) {
        if let Some(tenant_id) = Self::tenant_logo_id(scope, kind) {
            for (mime, extension) in ALLOWED_MIME {
                if keep_mime == Some(*mime) {
                    continue;
                }
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
            if keep_mime == Some(*mime) {
                continue;
            }
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

    /// PMS-1318: the (scope, kind) pairs whose stored path does NOT begin with
    /// the tenant, and the directory each one shares across tenants.
    ///
    /// Only `(Tenant, Logo)` goes through `ObjectKey`, so only it gets the
    /// `{tenant}/...` prefix every other kind of stored object has
    /// (`crate::storage::tests::every_object_kind_puts_its_tenant_first`). The
    /// other five are built from a local path in this module and sit in one
    /// shared directory per kind, which is the same shape PMS-960 removed for
    /// KB attachments and PMS-1234 removed for the logo itself.
    ///
    /// This is NOT live cross-tenant exposure: the serving routes are
    /// deliberately public with the id as the credential, so no key is
    /// presented that could name another tenant's object. What is missing is
    /// the property - a per-tenant bucket, quota, export or provider migration
    /// has no prefix to be built on, which is the reason the logo moved.
    ///
    /// PMS-1397 moves them. The list is here rather than in a comment so that
    /// closing it is a code change with a test behind it, and so a SIXTH pair
    /// added on the local-path layout fails below instead of joining them
    /// quietly.
    const NOT_TENANT_SCOPED: &[(AssetScope, BrandAssetKind, &str)] = &[
        (
            AssetScope::Tenant(Uuid::nil()),
            BrandAssetKind::Favicon,
            "tenant-favicons",
        ),
        (
            AssetScope::Tenant(Uuid::nil()),
            BrandAssetKind::Background,
            "tenant-backgrounds",
        ),
        (
            AssetScope::Company(Uuid::nil()),
            BrandAssetKind::Logo,
            "company-logos",
        ),
        (
            AssetScope::Company(Uuid::nil()),
            BrandAssetKind::Favicon,
            "company-favicons",
        ),
        (
            AssetScope::Company(Uuid::nil()),
            BrandAssetKind::Background,
            "company-backgrounds",
        ),
    ];

    fn store() -> BrandingAssetStore {
        BrandingAssetStore {
            root: PathBuf::from("/data/attachments"),
            logo_store: crate::storage::shared(),
            ledger: None,
        }
    }

    /// Exactly one pair is tenant-scoped, and it is the logo.
    ///
    /// `tenant_logo_id` is the classifier the store itself branches on, so
    /// asserting over it is asserting over the real behaviour rather than a
    /// restatement of the list. A sixth pair, or a pair moved onto `ObjectKey`
    /// without updating the list, fails here.
    #[test]
    fn the_unscoped_pairs_are_the_ones_pms_1318_found() {
        let every_pair = [
            (AssetScope::Tenant(Uuid::nil()), BrandAssetKind::Logo),
            (AssetScope::Tenant(Uuid::nil()), BrandAssetKind::Favicon),
            (AssetScope::Tenant(Uuid::nil()), BrandAssetKind::Background),
            (AssetScope::Company(Uuid::nil()), BrandAssetKind::Logo),
            (AssetScope::Company(Uuid::nil()), BrandAssetKind::Favicon),
            (AssetScope::Company(Uuid::nil()), BrandAssetKind::Background),
        ];

        for (scope, kind) in every_pair {
            let through_object_key = BrandingAssetStore::tenant_logo_id(scope, kind).is_some();
            let listed = NOT_TENANT_SCOPED
                .iter()
                .any(|(s, k, _)| s.subdir_prefix() == scope.subdir_prefix() && *k == kind);
            assert_ne!(
                through_object_key, listed,
                "{}/{:?} is both tenant-scoped and listed as not, or neither;                  PMS-1397 closes this list and the entry comes off then",
                scope.subdir_prefix(),
                kind
            );
        }
    }

    /// Each listed pair really does land in a directory shared across tenants.
    ///
    /// Asserted against the path the store builds, so the list cannot go stale
    /// by describing a layout the code stopped producing.
    #[test]
    fn an_unscoped_pair_shares_one_directory_across_tenants() {
        let s = store();
        for (scope, kind, directory) in NOT_TENANT_SCOPED {
            let path = s.path_for(*scope, *kind, "image/png");
            let relative = path
                .strip_prefix("/data/attachments")
                .expect("the store builds under its root");
            let first = relative
                .components()
                .next()
                .expect("a path has a first component")
                .as_os_str()
                .to_string_lossy()
                .to_string();
            assert_eq!(
                &first,
                directory,
                "the list says {directory} but the store writes {}",
                relative.display()
            );
        }
    }
}
