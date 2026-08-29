//! The image types a public, unauthenticated route may serve (PMS-941).
//!
//! Three surfaces now store an image and hand out a URL that no client can
//! authenticate: the tenant logo a recipient's mail client fetches out of an
//! email (MAPPS-429), the image embedded in a KB article (PMS-923), and the
//! image embedded in a ticket description or note (PMS-941). All three fetch as
//! `<img src>`, all three are served from the API origin, and all three
//! therefore have to agree on exactly one question: which types are safe to
//! hand back.
//!
//! SVG is deliberately absent from that list. It is a script-capable document,
//! and serving one from the API origin to an unauthenticated client is a stored
//! XSS on that origin. The refusal is at upload, not at read, so a hostile file
//! never reaches disk in the first place.
//!
//! This module is the single definition, guarded by a test below: call
//! [`check_inline_image_mime`], do not copy the list. A second copy is how the
//! three surfaces drift, and drift here means one route quietly accepting a
//! type the other two spent a paragraph explaining they refuse.

use crate::utils::error::{AppError, AppResult};

/// Types a browser and a mail client both render without a plugin.
///
/// See the module header for why SVG is not here and never should be.
pub const ALLOWED_INLINE_IMAGE_MIME: &[&str] =
    &["image/png", "image/jpeg", "image/webp", "image/gif"];

/// Normalise and validate a client-supplied content type.
///
/// Browsers append parameters (`image/png; charset=binary`), so the type is cut
/// at the first `;` before matching, and matching is case-insensitive because
/// the header is. The returned value is the canonical `&'static str` from the
/// list, so what gets stored is what this module named rather than whatever
/// casing the upload arrived in.
pub fn check_inline_image_mime(raw: &str) -> AppResult<&'static str> {
    let base = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    ALLOWED_INLINE_IMAGE_MIME
        .iter()
        .find(|m| **m == base)
        .copied()
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "Unsupported image type `{base}`; use PNG, JPEG, WebP or GIF"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_is_refused_on_every_public_image_surface() {
        assert!(
            check_inline_image_mime("image/svg+xml").is_err(),
            "SVG is a script-capable document served from the API origin to \
             unauthenticated clients, so it is refused rather than sanitised"
        );
        assert!(check_inline_image_mime("text/html").is_err());
        assert!(check_inline_image_mime("application/octet-stream").is_err());
        assert!(check_inline_image_mime("").is_err());
        for ok in ALLOWED_INLINE_IMAGE_MIME {
            assert_eq!(check_inline_image_mime(ok).unwrap(), *ok);
        }
    }

    #[test]
    fn a_browser_supplied_header_carries_parameters_and_arbitrary_case() {
        assert_eq!(
            check_inline_image_mime("IMAGE/PNG; charset=binary").unwrap(),
            "image/png"
        );
        assert_eq!(
            check_inline_image_mime("  image/JPEG  ").unwrap(),
            "image/jpeg"
        );
    }

    /// Mirrors `utils::net::exactly_one_definition_in_the_crate`. A second copy
    /// of this check is how the logo, the KB image and the ticket inline image
    /// drift apart on the one question they must answer identically.
    #[test]
    fn exactly_one_definition_in_the_crate() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // Assembled at runtime so this test's own source does not match it.
        let needle = format!("fn {}", "check_inline_image_mime");
        let mut definitions = Vec::new();
        let mut pending = vec![src.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read source directory") {
                let path = entry.expect("read directory entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let source = std::fs::read_to_string(&path).expect("read source file");
                    if source.contains(&needle) {
                        definitions.push(path);
                    }
                }
            }
        }
        // `read_dir` order is filesystem-dependent; sort so a failure names the
        // same list every run.
        definitions.sort();
        assert_eq!(
            definitions,
            vec![src.join("utils").join("inline_image.rs")],
            "check_inline_image_mime must have exactly one definition, in \
             utils/inline_image.rs; call it, do not copy it"
        );
    }
}
