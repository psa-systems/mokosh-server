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

use uuid::Uuid;

use super::branding::PUBLIC_TENANT_PATH_PREFIX;
use std::sync::Arc;

use crate::storage::{FileLedger, FileRecord, ObjectKey, ObjectProvider};
use crate::utils::error::{AppError, AppResult};

/// The on-disk suffix each allowed type is stored under. This table names
/// extensions only: what is *allowed* is `utils::inline_image`, shared with the
/// other two publicly-readable image routes (PMS-941), and a test below keeps
/// the two in step so a type can never be accepted with no extension to store
/// it under.
const EXTENSIONS: &[(&str, &str)] = &[
    ("image/png", "png"),
    ("image/jpeg", "jpg"),
    ("image/webp", "webp"),
    ("image/gif", "gif"),
];

/// Default cap when `TENANT_LOGO_MAX_BYTES` is unset. 1 MiB, a twenty-fifth of
/// the 25 MiB attachment cap, on purpose: this one is embedded in every email a
/// client receives, so it is a size that has to stay polite.
const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

/// PMS-783 (F10): the box a rendered logo occupies, in CSS pixels. One pair of
/// numbers for every renderer: [`super::identity::OrgIdentity::logo_html`] uses
/// it for both the CSS box and the intrinsic `width` / `height` attributes, so
/// a client can reserve the space before the bytes arrive instead of reflowing
/// the message around it. If the box ever moves, a downscale-on-upload step
/// (PMS-784) takes its target from here too.
pub const LOGO_BOX_WIDTH: u32 = 220;
pub const LOGO_BOX_HEIGHT: u32 = 56;

#[derive(Clone, Debug)]
pub struct TenantLogoConfig {
    pub max_bytes: u64,
}

impl TenantLogoConfig {
    pub fn from_env() -> Self {
        let max_bytes = std::env::var("TENANT_LOGO_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_BYTES);
        Self { max_bytes }
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
    EXTENSIONS
        .iter()
        .find(|(m, _)| *m == mime)
        .map(|(_, ext)| *ext)
        .unwrap_or("bin")
}

/// Normalise and validate an uploaded content type.
///
/// PMS-941: the decision itself lives in `utils::inline_image`, because the
/// logo, the KB article image and the ticket inline image are the same bargain
/// (an `<img>` that cannot authenticate, served from the API origin) and must
/// answer this question identically. Kept as a named function here so the call
/// sites in this module read the same as before.
pub fn check_mime(raw: &str) -> AppResult<&'static str> {
    crate::utils::inline_image::check_inline_image_mime(raw)
}

#[derive(Clone, Debug)]
pub struct TenantLogoStore {
    config: TenantLogoConfig,
    /// PMS-910: where the bytes go. This module no longer knows.
    store: Arc<dyn ObjectProvider>,
    /// PMS-957: one row per stored file. A logo is the one object written to
    /// the same key over and over, so its row is upserted rather than added to,
    /// and a tenant's usage counts one logo however many times it is replaced.
    ledger: Option<FileLedger>,
}

impl TenantLogoStore {
    pub fn new(config: TenantLogoConfig) -> Self {
        Self {
            config,
            store: crate::storage::shared(),
            ledger: None,
        }
    }

    /// PMS-957: give this store a database to record uploads in.
    ///
    /// Optional because the public read router builds one from configuration
    /// alone and has no pool, and recording is a property of STORING a logo
    /// rather than of serving one.
    pub fn with_ledger(mut self, db: crate::db::Database) -> Self {
        self.ledger = Some(FileLedger::new(db));
        self
    }

    pub fn max_bytes(&self) -> u64 {
        self.config.max_bytes
    }

    /// Write the logo, replacing whatever this tenant had. Returns the mime it
    /// was stored under, which the caller records in `branding.logo_mime`.
    ///
    /// The previous file is removed first, because a format change leaves the
    /// old extension behind and two files for one tenant is one file too many.
    ///
    /// PMS-783 decision: the bytes are stored at whatever resolution was
    /// uploaded, because downscaling means an image decoder in this path and
    /// that dependency call is a person's, not this change's. Tracked in
    /// PMS-784; until it lands, `max_bytes` is the only bound on a logo.
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
        let key = ObjectKey::tenant_logo(tenant_id, extension_for(mime));
        self.store.put(&key, bytes).await?;
        if let Some(ledger) = &self.ledger {
            // Keyed on the TENANT, not a fresh id: there is one logo per tenant
            // and replacing it must not add a second row to the rollup.
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
        Ok(mime)
    }

    /// Read the stored bytes for a tenant whose branding says it has a logo.
    pub async fn read(&self, tenant_id: Uuid, mime: &str) -> AppResult<Vec<u8>> {
        let mime = check_mime(mime)?;
        self.store
            .read(&ObjectKey::tenant_logo(tenant_id, extension_for(mime)))
            .await
            .map_err(|_| AppError::NotFound("Logo".to_string()))
    }

    /// Delete every stored format for this tenant. Best effort: a logo the
    /// branding no longer points at is invisible, so a failed unlink must not
    /// fail the request that cleared it.
    pub async fn remove(&self, tenant_id: Uuid) {
        for (_, extension) in EXTENSIONS {
            let _ = self
                .store
                .delete(&ObjectKey::tenant_logo(tenant_id, *extension))
                .await;
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

    /// A type the shared allowlist accepts but this table has no row for would
    /// be stored as `{tenant}.bin`, so the two lists have to move together.
    #[test]
    fn every_allowed_type_has_an_extension_to_store_it_under() {
        for mime in crate::utils::inline_image::ALLOWED_INLINE_IMAGE_MIME {
            assert_ne!(
                extension_for(mime),
                "bin",
                "{mime} is allowed but has no row in EXTENSIONS"
            );
        }
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
        let mut seen: Vec<&str> = EXTENSIONS.iter().map(|(_, ext)| *ext).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "two mime types share an extension");
    }
}
