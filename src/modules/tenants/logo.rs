//! MAPPS-429: the tenant's logo, uploaded by an admin and served to anyone.
//!
//! Storage follows PMS-483's ticket attachments: a file on local disk under a
//! configured root, path-derived from the tenant id, with the row (here, the
//! `tenants.branding` JSON) holding the metadata. It deliberately does NOT
//! reuse `ticket_attachments`, which is scoped to a note on a ticket.
//!
//! One file per tenant, overwritten in place. A logo has no history worth
//! keeping and versioning it would only invite a cache-busting problem.
//!
//! # Why the read side is public
//!
//! The two places this image has to appear are a client's browser on
//! `/request-forms/{token}` and a client's MAIL CLIENT rendering the email that
//! links there. Neither has a session, and a mail client will not authenticate,
//! so an authenticated route could never serve it. The bytes are a company's
//! logo, which is the least private asset an MSP owns, and the route is keyed
//! by a v4 tenant uuid, so this exposes branding to whoever already holds the
//! tenant id.

use std::path::PathBuf;

use uuid::Uuid;

use super::branding::PUBLIC_TENANT_PATH_PREFIX;
use crate::utils::error::{AppError, AppResult};

/// Formats a browser and a mail client both render without a plugin. Anything
/// else is refused rather than stored and served back as `octet-stream`.
///
/// SVG is deliberately absent: it is a script-capable document, and this route
/// serves it from the API origin to unauthenticated clients.
const ALLOWED_MIME: &[(&str, &str)] = &[
    ("image/png", "png"),
    ("image/jpeg", "jpg"),
    ("image/webp", "webp"),
    ("image/gif", "gif"),
];

/// Default cap when `TENANT_LOGO_MAX_BYTES` is unset. Two orders of magnitude
/// under the 25 MiB attachment cap on purpose: this one is embedded in every
/// email a client receives, so it is a size that has to stay polite.
const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

/// Subdirectory under the shared upload root. Sharing the root with attachments
/// keeps deployments to one mounted volume; the subdirectory keeps a logo from
/// ever colliding with a `{tenant_id}/{attachment_id}` path.
const SUBDIR: &str = "tenant-logos";

#[derive(Clone, Debug)]
pub struct TenantLogoConfig {
    pub dir: PathBuf,
    pub max_bytes: u64,
}

impl TenantLogoConfig {
    pub fn from_env() -> Self {
        let root = std::env::var("ATTACHMENT_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./attachments"));
        let max_bytes = std::env::var("TENANT_LOGO_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_BYTES);
        Self {
            dir: root.join(SUBDIR),
            max_bytes,
        }
    }

    fn path_for(&self, tenant_id: Uuid, mime: &str) -> PathBuf {
        self.dir
            .join(format!("{tenant_id}.{}", extension_for(mime)))
    }
}

impl Default for TenantLogoConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// The extension a stored logo takes, or `bin` for a mime that never passed
/// [`check_mime`] (unreachable through the routes; kept total for callers).
fn extension_for(mime: &str) -> &'static str {
    ALLOWED_MIME
        .iter()
        .find(|(m, _)| *m == mime)
        .map(|(_, ext)| *ext)
        .unwrap_or("bin")
}

/// Normalise and validate an uploaded content type.
///
/// Browsers append parameters (`image/png; charset=binary`), so the type is cut
/// at the first `;` before matching, and matching is case-insensitive because
/// the header is.
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
                "Unsupported image type `{base}`; use PNG, JPEG, WebP or GIF"
            ))
        })
}

#[derive(Clone, Debug)]
pub struct TenantLogoStore {
    config: TenantLogoConfig,
}

impl TenantLogoStore {
    pub fn new(config: TenantLogoConfig) -> Self {
        Self { config }
    }

    pub fn max_bytes(&self) -> u64 {
        self.config.max_bytes
    }

    /// Write the logo, replacing whatever this tenant had. Returns the mime it
    /// was stored under, which the caller records in `branding.logo_mime`.
    ///
    /// The previous file is removed first, because a format change leaves the
    /// old extension behind and two files for one tenant is one file too many.
    pub async fn store(
        &self,
        tenant_id: Uuid,
        mime: &str,
        bytes: &[u8],
    ) -> AppResult<&'static str> {
        let mime = check_mime(mime)?;
        if bytes.is_empty() {
            return Err(AppError::BadRequest("The uploaded file is empty".into()));
        }
        if bytes.len() as u64 > self.config.max_bytes {
            return Err(AppError::BadRequest(format!(
                "Logo is larger than the {} KiB limit",
                self.config.max_bytes / 1024
            )));
        }

        self.remove(tenant_id).await;
        tokio::fs::create_dir_all(&self.config.dir)
            .await
            .map_err(|e| AppError::Internal(format!("create logo dir: {e}")))?;
        tokio::fs::write(self.config.path_for(tenant_id, mime), bytes)
            .await
            .map_err(|e| AppError::Internal(format!("write logo: {e}")))?;
        Ok(mime)
    }

    /// Read the stored bytes for a tenant whose branding says it has a logo.
    pub async fn read(&self, tenant_id: Uuid, mime: &str) -> AppResult<Vec<u8>> {
        let mime = check_mime(mime)?;
        tokio::fs::read(self.config.path_for(tenant_id, mime))
            .await
            .map_err(|_| AppError::NotFound("Logo".to_string()))
    }

    /// Delete every stored format for this tenant. Best effort: a logo the
    /// branding no longer points at is invisible, so a failed unlink must not
    /// fail the request that cleared it.
    pub async fn remove(&self, tenant_id: Uuid) {
        for (mime, _) in ALLOWED_MIME {
            let _ = tokio::fs::remove_file(self.config.path_for(tenant_id, mime)).await;
        }
    }
}

/// Path a client fetches the logo from. Relative on purpose: the SPA joins it
/// with the API base it already knows, and the email composer joins it with the
/// public API base it is configured with. Nothing here can know both.
pub fn logo_path(tenant_id: Uuid) -> String {
    format!("{PUBLIC_TENANT_PATH_PREFIX}{tenant_id}/logo")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_renderable_image_types_are_accepted() {
        assert_eq!(check_mime("image/png").unwrap(), "image/png");
        assert_eq!(
            check_mime("IMAGE/PNG; charset=binary").unwrap(),
            "image/png",
            "a browser-supplied header carries parameters and arbitrary case"
        );
        assert!(check_mime("application/pdf").is_err());
        assert!(
            check_mime("image/svg+xml").is_err(),
            "SVG is a script-capable document served from the API origin to \
             unauthenticated clients, so it is refused rather than sanitised"
        );
    }

    #[test]
    fn a_logo_path_is_relative_so_both_callers_can_join_it() {
        let id = Uuid::nil();
        let path = logo_path(id);
        assert_eq!(
            path,
            "/api/v1/public/tenants/{id}/logo".replace("{id}", &id.to_string())
        );
        assert!(
            !path.starts_with("http"),
            "an absolute URL here would bake in one origin and be wrong for the other caller"
        );
    }

    #[test]
    fn each_accepted_type_has_its_own_extension() {
        // Two types sharing an extension would let a format change orphan the
        // previous file under a path `remove` still visits, but `store` would
        // then overwrite a file it believes is a different format.
        let mut seen: Vec<&str> = ALLOWED_MIME.iter().map(|(_, ext)| *ext).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "two mime types share an extension");
    }
}
