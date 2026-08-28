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
//! The tenant logo (`tenant-logos/`) is served by the legacy MAPPS-429
//! path (`src/modules/tenants/logo.rs`) so the in-flight tenant logo
//! upload flow keeps working unchanged; this module owns the two new
//! tenant kinds (favicon + background) plus every Company kind.
//!
//! Same MIME allowlist as the tenant logo (`image/png|jpeg|webp|gif`);
//! SVG stays refused. Per-kind size caps default to sensible values
//! and can be tuned per deployment via env.

use std::path::PathBuf;

use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};

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

    fn env_var(self, scope: AssetScope) -> &'static str {
        match (scope, self) {
            (AssetScope::Tenant(_), Self::Logo) => "TENANT_LOGO_MAX_BYTES",
            (AssetScope::Tenant(_), Self::Favicon) => "BRANDING_TENANT_FAVICON_MAX_BYTES",
            (AssetScope::Tenant(_), Self::Background) => "BRANDING_TENANT_BACKGROUND_MAX_BYTES",
            (AssetScope::Company(_), Self::Logo) => "BRANDING_COMPANY_LOGO_MAX_BYTES",
            (AssetScope::Company(_), Self::Favicon) => "BRANDING_COMPANY_FAVICON_MAX_BYTES",
            (AssetScope::Company(_), Self::Background) => "BRANDING_COMPANY_BACKGROUND_MAX_BYTES",
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
                "unsupported image type `{base}`; use PNG, JPEG, WebP or GIF"
            ))
        })
}

#[derive(Clone, Debug)]
pub struct BrandingAssetStore {
    root: PathBuf,
}

/// Type alias kept during the phase-B rollout so existing callers
/// still compile; new code uses [`BrandingAssetStore`] directly.
pub type CompanyAssetStore = BrandingAssetStore;

impl BrandingAssetStore {
    pub fn from_env() -> Self {
        let root = std::env::var("ATTACHMENT_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./attachments"));
        Self { root }
    }

    pub fn max_bytes(&self, kind: BrandAssetKind, scope: AssetScope) -> u64 {
        std::env::var(kind.env_var(scope))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| kind.default_max_bytes())
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
            return Err(AppError::BadRequest("the uploaded file is empty".into()));
        }
        let cap = self.max_bytes(kind, scope);
        if bytes.len() as u64 > cap {
            return Err(AppError::BadRequest(format!(
                "image is larger than the {} KiB limit",
                cap / 1024
            )));
        }
        self.remove(scope, kind).await;
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
        tokio::fs::read(self.path_for(scope, kind, mime))
            .await
            .map_err(|_| AppError::NotFound("Asset".to_string()))
    }

    /// Remove every stored format for a (scope, kind) pair. Best-
    /// effort: an unreachable file the branding row no longer points
    /// at cannot fail the request that cleared the row.
    pub async fn remove(&self, scope: AssetScope, kind: BrandAssetKind) {
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
