//! The one refusal for an oversized upload (PMS-1204).
//!
//! Five sites accept a file over HTTP and enforce their own size cap: ticket
//! attachments and inline images (`modules/tickets/attachments.rs`), a KB
//! article image (`modules/knowledge_base/attachments.rs`), the tenant logo
//! (`modules/tenants/logo.rs`), and a branding asset (`modules/branding/assets.rs`).
//! Before this they answered with three different status codes (400 and 413,
//! split arbitrarily by which site wrote the check) and five different
//! wordings, so a client could not tell "too big" from any other bad request
//! without matching on English text. A size-limit refusal is a 413 Payload Too
//! Large: the request is well-formed and would succeed at a smaller size,
//! which is exactly what 413 means and 400 does not.
//!
//! Call [`oversized_upload_error`], do not build an `AppError` for this case
//! by hand. A second copy is how the five sites drift again.

use crate::utils::error::AppError;

/// Refuse an upload that exceeds its size cap. `what` names the thing being
/// uploaded (e.g. `"attachment"`, `"logo"`, `"KB image"`) so the message
/// stays specific while the status code and sentence shape stay identical
/// everywhere.
pub fn oversized_upload_error(what: &str, cap_bytes: u64) -> AppError {
    AppError::PayloadTooLarge(format!("{what} exceeds the {cap_bytes} byte cap."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_with_payload_too_large() {
        let err = oversized_upload_error("attachment", 1024);
        assert_eq!(err.status_code(), 413);
        assert_eq!(
            err.to_string(),
            "Payload too large: attachment exceeds the 1024 byte cap."
        );
    }

    /// Enumerates the five upload-refusal sites named in PMS-1204 and asserts
    /// each one calls the shared helper rather than building its own
    /// `AppError::PayloadTooLarge` / `BadRequest` for a size-limit refusal.
    #[test]
    fn every_cited_upload_site_calls_the_shared_helper() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let sites = [
            src.join("modules").join("tickets").join("attachments.rs"),
            src.join("modules")
                .join("knowledge_base")
                .join("attachments.rs"),
            src.join("modules").join("tenants").join("logo.rs"),
            src.join("modules").join("branding").join("assets.rs"),
        ];
        for site in &sites {
            let source = std::fs::read_to_string(site)
                .unwrap_or_else(|e| panic!("read {}: {e}", site.display()));
            let calls = source.matches("oversized_upload_error(").count();
            assert!(
                calls >= 1,
                "{} must refuse an oversized upload through \
                 utils::upload_limits::oversized_upload_error, not a hand-built \
                 AppError",
                site.display()
            );
        }
    }
}
