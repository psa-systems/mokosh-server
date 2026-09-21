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
//!
//! ## The route also needs its own `DefaultBodyLimit` (PMS-1233)
//!
//! `oversized_upload_error` is a refusal a handler returns; it never runs if
//! axum rejects the body first. Every multipart extractor axum ships wraps the
//! body in a 2 MiB `Limited` reader whenever a route carries no explicit
//! `axum::extract::DefaultBodyLimit`, and nothing in this crate raised that
//! framework default to match a route's real, larger cap. A cap above 2 MiB
//! (ticket attachments default to 25 MiB) could therefore never be reached:
//! `field.bytes()` fails inside axum before this module's check runs, and the
//! client gets a generic 400 regardless of whether the file was under or over
//! the app's own cap. `body_limit_bytes` is the value each of those four
//! routes must pass to `DefaultBodyLimit::max` (via `.layer(...)` on the
//! route, matching the app's other multipart size caps to the app's shape:
//! sized above the real cap, not equal to it).

use crate::utils::error::AppError;

/// Refuse an upload that exceeds its size cap. `what` names the thing being
/// uploaded (e.g. `"attachment"`, `"logo"`, `"KB image"`) so the message
/// stays specific while the status code and sentence shape stay identical
/// everywhere.
pub fn oversized_upload_error(what: &str, cap_bytes: u64) -> AppError {
    AppError::PayloadTooLarge(format!("{what} exceeds the {cap_bytes} byte cap."))
}

/// Multipart framing (the boundary delimiter and each part's own headers)
/// rides inside the body axum's `DefaultBodyLimit` measures, on top of the
/// file bytes it wraps. A limit set to exactly a route's byte cap therefore
/// refuses an AT-CAP file the instant its framing is counted, which is exactly
/// what happened to the 2 MiB branding-background cap. This margin is
/// generous rather than exact: a request that lands inside it but still over
/// the real cap stops at the same [`oversized_upload_error`] refusal, so
/// oversizing the framework limit costs nothing.
const MULTIPART_OVERHEAD_BYTES: u64 = 64 * 1024;

/// The `axum::extract::DefaultBodyLimit::max` value for a route whose real
/// refusal is `oversized_upload_error(_, cap_bytes)`. Call this when building
/// the route, not the app's own logical cap, so an at-cap upload is accepted
/// and an over-cap one still reaches the app's own 413 rather than axum's.
pub fn body_limit_bytes(cap_bytes: u64) -> usize {
    cap_bytes.saturating_add(MULTIPART_OVERHEAD_BYTES) as usize
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
            // PMS-1290: an uploaded vCard file.
            src.join("modules")
                .join("contact_sync")
                .join("file_import.rs"),
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

    #[test]
    fn body_limit_adds_the_multipart_overhead_margin() {
        assert_eq!(
            body_limit_bytes(2 * 1024 * 1024),
            2 * 1024 * 1024 + 64 * 1024
        );
    }

    /// PMS-1233: the four routes that own an upload cap must also raise axum's
    /// `DefaultBodyLimit` to match it, or the framework's own 2 MiB default
    /// pre-empts every one of those checks. Enumerated by the router-building
    /// file, since that (not the service module the size check lives in, some
    /// of which `oversized_upload_error` already covers above) is where the
    /// route and its `DefaultBodyLimit` are wired together.
    #[test]
    fn every_upload_route_file_sizes_its_default_body_limit() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let sites = [
            src.join("modules").join("tickets").join("attachments.rs"),
            src.join("modules")
                .join("knowledge_base")
                .join("attachments.rs"),
            src.join("modules").join("tenants").join("routes.rs"),
            src.join("modules").join("branding").join("routes.rs"),
            src.join("modules").join("contact_sync").join("routes.rs"),
        ];
        for site in &sites {
            let source = std::fs::read_to_string(site)
                .unwrap_or_else(|e| panic!("read {}: {e}", site.display()));
            assert!(
                source.contains("body_limit_bytes(") && source.contains("DefaultBodyLimit"),
                "{} must raise axum::extract::DefaultBodyLimit via \
                 utils::upload_limits::body_limit_bytes on its upload route, or \
                 axum's own 2 MiB default pre-empts the app's cap",
                site.display()
            );
        }
    }
}
