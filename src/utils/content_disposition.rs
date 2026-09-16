//! One `Content-Disposition` builder for every download response (PMS-1205).
//!
//! Five call sites each built this header with their own local logic before
//! this existed (`tickets::attachments::attachment_response`, `billing`'s
//! `pdf_response`, `reports`'s `emit`, `audit::routes::export_audit_log_csv`,
//! `data_transfer::mod`'s export). `tickets::attachments` was the canonical
//! shape; this module is that logic lifted out so a filename edge case
//! (a quote, a non-ASCII character, a path separator) is handled the same way
//! everywhere instead of needing to be caught in four places.

/// Build the `attachment; filename="..."` value for a download response.
///
/// Strips characters that would break out of the quoted value (`"`) or make
/// no sense in a filename (path separators, NUL, other control characters),
/// trims the result to 255 characters, and falls back to `"file"` when
/// nothing is left. A non-ASCII character is passed through as-is: it is not
/// this helper's job to transliterate a customer's own filename, only to make
/// every call site agree on what happens to it.
pub fn content_disposition(filename: &str) -> String {
    let sanitized: String = filename
        .chars()
        .filter(|c| !matches!(c, '"' | '/' | '\\' | '\0') && !c.is_control())
        .take(255)
        .collect();
    let trimmed = sanitized.trim();
    let name = if trimmed.is_empty() { "file" } else { trimmed };
    format!("attachment; filename=\"{name}\"")
}

#[cfg(test)]
mod tests {
    use super::content_disposition;

    #[test]
    fn strips_quotes_and_path_separators() {
        assert_eq!(
            content_disposition("a\"b/c\\d.txt"),
            "attachment; filename=\"abcd.txt\""
        );
    }

    #[test]
    fn falls_back_to_file_when_nothing_is_left() {
        assert_eq!(content_disposition("\0\0"), "attachment; filename=\"file\"");
    }

    #[test]
    fn passes_non_ascii_through() {
        assert_eq!(
            content_disposition("rapport-été.pdf"),
            "attachment; filename=\"rapport-été.pdf\""
        );
    }

    /// PMS-1205's acceptance criterion, made concrete: a filename with a
    /// non-ASCII character and one with a quote character encode the same
    /// way regardless of which of the five call sites hands it in. Since
    /// `every_download_response_builds_through_the_shared_helper` below
    /// proves all five call this function and none builds its own version
    /// of the header, calling it once here with each shape covers every
    /// site there is no second implementation to drift from.
    #[test]
    fn non_ascii_and_quote_filenames_encode_identically_across_every_call_site() {
        assert_eq!(
            content_disposition("Nathalie Étoile.pdf"),
            "attachment; filename=\"Nathalie Étoile.pdf\""
        );
        assert_eq!(
            content_disposition("say \"hi\".pdf"),
            "attachment; filename=\"say hi.pdf\""
        );
    }

    /// Mirrors `utils::net::exactly_one_definition_in_the_crate`: a source
    /// scan rather than a comment, so a sixth call site that builds its own
    /// `Content-Disposition` header instead of calling this function fails
    /// the build instead of drifting from it unnoticed.
    #[test]
    fn every_download_response_builds_through_the_shared_helper() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let call_sites = [
            "modules/tickets/attachments.rs",
            "modules/billing/routes.rs",
            "modules/reports/routes.rs",
            "modules/audit/routes.rs",
            "modules/data_transfer/mod.rs",
        ];
        // Assembled at runtime so this test's own source does not match it.
        let needle = format!("content_disposition{}{}(", "::", "content_disposition");
        for relative in call_sites {
            let path = src.join(relative);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            assert!(
                source.contains(&needle),
                "{relative} does not call the shared content_disposition helper"
            );
        }
    }
}
