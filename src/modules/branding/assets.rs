//! MAPPS-618 phase B (mokosh-branding prompt 002): parameterized asset
//! store for Company-scoped branding uploads (logo, favicon,
//! background). Mirrors [`crate::modules::tenants::logo`] one-for-one
//! at Company scope; the tenant module stays untouched so an
//! in-flight tenant-logo upload does not risk regressing.
//!
//! Storage layout under `$ATTACHMENT_DIR`:
//!
//! ```text
//! attachments/
//!   company-logos/{company_id}.{ext}
//!   company-favicons/{company_id}.{ext}
//!   company-backgrounds/{company_id}.{ext}
//! ```
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

/// The three brand asset kinds a Company can upload. Each maps to a
/// distinct subdirectory + its own size cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompanyAssetKind {
    Logo,
    Favicon,
    Background,
}

impl CompanyAssetKind {
    fn subdir(self) -> &'static str {
        match self {
            Self::Logo => "company-logos",
            Self::Favicon => "company-favicons",
            Self::Background => "company-backgrounds",
        }
    }

    fn env_var(self) -> &'static str {
        match self {
            Self::Logo => "BRANDING_COMPANY_LOGO_MAX_BYTES",
            Self::Favicon => "BRANDING_COMPANY_FAVICON_MAX_BYTES",
            Self::Background => "BRANDING_COMPANY_BACKGROUND_MAX_BYTES",
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
pub struct CompanyAssetStore {
    root: PathBuf,
}

impl CompanyAssetStore {
    pub fn from_env() -> Self {
        let root = std::env::var("ATTACHMENT_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./attachments"));
        Self { root }
    }

    pub fn max_bytes(&self, kind: CompanyAssetKind) -> u64 {
        std::env::var(kind.env_var())
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| kind.default_max_bytes())
    }

    fn dir_for(&self, kind: CompanyAssetKind) -> PathBuf {
        self.root.join(kind.subdir())
    }

    fn path_for(&self, kind: CompanyAssetKind, company_id: Uuid, mime: &str) -> PathBuf {
        self.dir_for(kind)
            .join(format!("{company_id}.{}", extension_for(mime)))
    }

    /// Store the asset, overwriting whatever the Company had for this
    /// kind. Returns the normalized MIME the caller records in the
    /// branding JSONB.
    pub async fn store(
        &self,
        kind: CompanyAssetKind,
        company_id: Uuid,
        mime: &str,
        bytes: &[u8],
    ) -> AppResult<&'static str> {
        let mime = check_mime(mime)?;
        if bytes.is_empty() {
            return Err(AppError::BadRequest("the uploaded file is empty".into()));
        }
        let cap = self.max_bytes(kind);
        if bytes.len() as u64 > cap {
            return Err(AppError::BadRequest(format!(
                "image is larger than the {} KiB limit",
                cap / 1024
            )));
        }
        self.remove(kind, company_id).await;
        tokio::fs::create_dir_all(self.dir_for(kind))
            .await
            .map_err(|e| AppError::Internal(format!("create asset dir: {e}")))?;
        tokio::fs::write(self.path_for(kind, company_id, mime), bytes)
            .await
            .map_err(|e| AppError::Internal(format!("write asset: {e}")))?;
        Ok(mime)
    }

    pub async fn read(
        &self,
        kind: CompanyAssetKind,
        company_id: Uuid,
        mime: &str,
    ) -> AppResult<Vec<u8>> {
        let mime = check_mime(mime)?;
        tokio::fs::read(self.path_for(kind, company_id, mime))
            .await
            .map_err(|_| AppError::NotFound("Asset".to_string()))
    }

    /// Remove every stored format for a (kind, Company) pair. Best-
    /// effort: an unreachable file the branding row no longer points
    /// at cannot fail the request that cleared the row.
    pub async fn remove(&self, kind: CompanyAssetKind, company_id: Uuid) {
        for (mime, _) in ALLOWED_MIME {
            let _ = tokio::fs::remove_file(self.path_for(kind, company_id, mime)).await;
        }
    }
}

/// Public-URL path a client fetches this asset from. Relative on
/// purpose: SPA joins with `API_BASE`; the email composer joins with
/// the configured public base.
pub fn asset_path(kind: CompanyAssetKind, company_id: Uuid) -> String {
    format!(
        "/api/v1/public/companies/{company_id}/{}",
        match kind {
            CompanyAssetKind::Logo => "logo",
            CompanyAssetKind::Favicon => "favicon",
            CompanyAssetKind::Background => "background",
        }
    )
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
        let p = asset_path(CompanyAssetKind::Logo, id);
        assert!(p.starts_with("/api/v1/public/companies/"));
        assert!(p.ends_with("/logo"));
    }
}
