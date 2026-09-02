//! Invisible-character normalization for user-supplied text (PMS-924).
//!
//! Lives in `mokosh-types` so the server, the shared DTO validators, and the
//! `mokosh-apps` WASM client all reach one definition instead of three copies.
//! `mokosh_server::utils::text` re-exports it and layers the HTTP middleware
//! that applies it to every JSON request body.

use std::borrow::Cow;

/// True for a character that renders as nothing and carries no meaning inside
/// a PSA field: the `Cf` format characters plus U+00AD (soft hyphen).
///
/// U+200C (ZWNJ) and U+200D (ZWJ) are deliberately absent: see
/// [`sanitize_invisible`].
fn is_removed(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                  // soft hyphen
        | '\u{200B}'                // zero width space
        | '\u{200E}' | '\u{200F}'   // left-to-right / right-to-left mark
        | '\u{202A}'..='\u{202E}'   // bidi embedding + override
        | '\u{2060}'..='\u{2064}'   // word joiner + invisible operators
        | '\u{2066}'..='\u{2069}'   // bidi isolates
        | '\u{FEFF}'                // BOM / zero width no-break space
    )
}

/// True for a whitespace character outside ASCII: U+00A0 (no-break space),
/// U+2007 (figure space), U+202F (narrow no-break space), U+3000 (ideographic
/// space), the U+2000-U+200A range, U+0085 (NEL), and friends. These reach a
/// validator looking like a space without being one.
fn is_exotic_space(c: char) -> bool {
    !c.is_ascii() && c.is_whitespace()
}

/// True for a character that is stripped from the *edges* of a value: ordinary
/// whitespace plus ZWNJ / ZWJ, which are meaningful inside a word and never at
/// its boundary.
fn is_edge_trim(c: char) -> bool {
    c.is_whitespace() || c == '\u{200C}' || c == '\u{200D}'
}

/// Remove characters that render as nothing, fold exotic spaces to a plain
/// space, and trim the result. Nothing is allocated unless a character actually
/// has to be rewritten: an already-clean value comes back as the input borrowed
/// byte for byte, and a value needing only a trim borrows a subslice of it.
///
/// [`Cow::Borrowed`] therefore means "no character was rewritten", NOT
/// "unchanged" - a borrowed trim is still a different value. A caller deciding
/// whether to write the result back must compare it with the input rather than
/// match on the `Cow` variant.
///
/// `str::trim` is not enough: it removes only characters where
/// `char::is_whitespace` is true, which excludes U+200B, U+FEFF, U+00AD,
/// U+200E / U+200F and the bidi and word-joiner ranges. `char::is_control` is
/// not enough either: it covers the `Cc` block only, so `is_control('\u{200B}')`
/// is `false`. A company named `Acme\u{200B}` and a company named `Acme` are
/// two different rows that render identically everywhere, and no query the user
/// can type explains the difference.
///
/// **Why ZWJ (U+200D) and ZWNJ (U+200C) are treated differently.** Every other
/// character in the removal set is decoration: dropping it cannot change what a
/// value means. ZWJ and ZWNJ can. They select ligature forms in Persian, Arabic
/// and Indic scripts, so removing one from a legitimate name spells a different
/// name, and they join emoji sequences, so removing one turns a single glyph
/// into several. They are therefore preserved *inside* a value and stripped
/// only at its edges, where they cannot be doing either job.
///
/// **Why secrets are exempt from the callers that apply this.** A password,
/// token, API key, webhook secret or recovery code is compared byte for byte
/// against something a person or a machine stored elsewhere. Any of those may
/// legitimately contain a no-break space or a format character, and silently
/// rewriting one turns a correct credential into a failed login with nothing in
/// the logs to explain it. This function has no opinion about field names; the
/// exemption list lives with the caller that walks a request body
/// (`mokosh_server::utils::text::SECRET_FIELD_NAMES`).
pub fn sanitize_invisible(value: &str) -> Cow<'_, str> {
    if !value.chars().any(|c| is_removed(c) || is_exotic_space(c)) {
        // Nothing to rewrite: a trim still borrows, so a clean value round-trips
        // byte-identical with no allocation.
        return Cow::Borrowed(value.trim_matches(is_edge_trim));
    }

    let mut rewritten = String::with_capacity(value.len());
    for c in value.chars() {
        if is_removed(c) {
            continue;
        }
        rewritten.push(if is_exotic_space(c) { ' ' } else { c });
    }
    let trimmed = rewritten.trim_matches(is_edge_trim);
    if trimmed.len() == rewritten.len() {
        Cow::Owned(rewritten)
    } else {
        Cow::Owned(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_value_round_trips_byte_identical_without_allocating() {
        for clean in [
            "Acme",
            "Acme Co.",
            "919-397-4144",
            "",
            "Ünïcödé is fine",
            "emoji 🎉 too",
        ] {
            let out = sanitize_invisible(clean);
            assert!(
                matches!(out, Cow::Borrowed(_)),
                "{clean:?} should not allocate"
            );
            assert_eq!(
                out.as_bytes(),
                clean.as_bytes(),
                "{clean:?} must not change"
            );
        }
    }

    #[test]
    fn format_characters_are_removed() {
        // One case per character the PMS-924 acceptance criteria enumerate.
        for (input, expected) in [
            ("Acme\u{200B}", "Acme"),   // zero width space
            ("Ac\u{200B}me", "Acme"),   // interior, too
            ("Acme\u{00AD}", "Acme"),   // soft hyphen
            ("Ac\u{00AD}me", "Acme"),   //
            ("Acme\u{200E}", "Acme"),   // left-to-right mark
            ("Acme\u{200F}", "Acme"),   // right-to-left mark
            ("Acme\u{2060}", "Acme"),   // word joiner
            ("Acme\u{2064}", "Acme"),   // invisible plus
            ("\u{FEFF}Acme", "Acme"),   // BOM
            ("Acme\u{202A}x", "Acmex"), // LRE
            ("Acme\u{202B}x", "Acmex"), // RLE
            ("Acme\u{202C}x", "Acmex"), // PDF
            ("Acme\u{202D}x", "Acmex"), // LRO
            ("Acme\u{202E}x", "Acmex"), // RLO
            ("Acme\u{2066}x", "Acmex"), // LRI
            ("Acme\u{2067}x", "Acmex"), // RLI
            ("Acme\u{2068}x", "Acmex"), // FSI
            ("Acme\u{2069}x", "Acmex"), // PDI
            ("\u{200B}\u{FEFF}Acme\u{00AD}", "Acme"),
        ] {
            assert_eq!(sanitize_invisible(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn exotic_spaces_become_a_plain_space() {
        for (input, expected) in [
            ("Acme\u{00A0}Co", "Acme Co"),    // no-break space
            ("Acme\u{202F}Co", "Acme Co"),    // narrow no-break space
            ("Acme\u{2007}Co", "Acme Co"),    // figure space
            ("Acme\u{3000}Co", "Acme Co"),    // ideographic space
            ("Acme\u{2009}Co", "Acme Co"),    // thin space
            ("\u{00A0}Acme\u{3000}", "Acme"), // folded, then trimmed away
        ] {
            assert_eq!(sanitize_invisible(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn interior_zwj_and_zwnj_survive_while_edge_ones_are_removed() {
        // Interior: meaningful, so byte-identical and non-allocating.
        for kept in ["\u{200C}", "\u{200D}"] {
            let input = format!("Ac{kept}me");
            let out = sanitize_invisible(&input);
            assert_eq!(
                out.as_bytes(),
                input.as_bytes(),
                "interior {kept:?} must survive"
            );
            assert!(matches!(out, Cow::Borrowed(_)));
        }
        // A real emoji ZWJ sequence must come out unchanged.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        assert_eq!(sanitize_invisible(family).as_bytes(), family.as_bytes());

        // Edges: decoration only, so removed.
        for (input, expected) in [
            ("\u{200C}Acme", "Acme"),
            ("Acme\u{200C}", "Acme"),
            ("\u{200D}Acme\u{200D}", "Acme"),
            // Interleaved with whitespace at the edge, both go.
            (" \u{200D} Acme \u{200C} ", "Acme"),
        ] {
            assert_eq!(sanitize_invisible(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn the_result_is_trimmed() {
        assert_eq!(sanitize_invisible("  Acme  "), "Acme");
        assert_eq!(sanitize_invisible("\n\tAcme\r\n"), "Acme");
        // Interior whitespace is left alone: only the edges are trimmed.
        assert_eq!(sanitize_invisible("  Acme  Co  "), "Acme  Co");
    }

    #[test]
    fn a_value_that_is_nothing_but_invisibles_collapses_to_empty() {
        assert_eq!(sanitize_invisible("\u{200B}\u{FEFF}\u{00A0}"), "");
    }

    #[test]
    fn the_reported_phone_number_survives_its_trailing_zero_width_space() {
        // MAPPS-581: this is the value that was rejected with no explanation.
        assert_eq!(sanitize_invisible("919-397-4144\u{200B}"), "919-397-4144");
    }

    #[test]
    fn control_characters_are_left_alone() {
        // Out of scope here: `Cc` is a different class from the `Cf` characters
        // this function targets, and a newline inside a description is content.
        assert_eq!(
            sanitize_invisible("line one\nline two"),
            "line one\nline two"
        );
    }
}
