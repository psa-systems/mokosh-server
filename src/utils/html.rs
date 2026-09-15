//! Escaping for the small amount of HTML mokosh composes by hand.
//!
//! `render_template` (`modules::notifications`) is a flat `{{key}}`
//! substitution with no conditionals, so any element that must sometimes
//! disappear has to be composed whole in Rust and handed over as a single key.
//! That means a handful of call sites build markup from values that did not
//! come from this crate, and they all need the same two escapes.
//!
//! Relocated here from `modules::forms::request_links` in PMS-761, where they
//! were private and therefore about to be copied.

/// Minimal escaping for the few characters that would break out of an
/// attribute or an element. Not a general-purpose sanitiser: the values passed
/// through it are operator configuration and tenant-set names, not documents.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The `<meta viewport>` tag both server-rendered HTML pages (`not_a_frontend`,
/// the provider-status page) declare, closing PMS-703's F19 for both in one
/// place (PMS-1201).
pub const PAGE_SHELL_VIEWPORT: &str =
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";

/// The page-shell CSS shared by every server-rendered HTML page: font stack,
/// margin, padding, base color and `color-scheme` (closing PMS-703's F20).
/// Only `max_width` is a content decision, since the status page's tables are
/// legitimately wider than the 404 page's two paragraphs (PMS-1201). A caller
/// embeds this inside its own `<style>` tag and may append page-specific rules
/// after it.
pub fn page_shell_css(max_width: &str) -> String {
    format!(
        "body{{font-family:system-ui,-apple-system,sans-serif;max-width:{max_width};margin:2rem auto;padding:0 1rem;color:#1a1a1a;color-scheme:light dark}}"
    )
}

/// Percent-encode a `mailto:` subject. Everything outside the unreserved set
/// is encoded, so a form name carrying a space, an ampersand or a quote cannot
/// truncate the URL or escape the attribute.
pub fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_attribute_and_element_breakouts() {
        assert_eq!(
            html_escape(r#"<a href="x">R&D</a>"#),
            "&lt;a href=&quot;x&quot;&gt;R&amp;D&lt;/a&gt;"
        );
    }

    #[test]
    fn ampersand_is_escaped_before_the_entities_it_introduces() {
        // `&` first, otherwise the `&` of `&quot;` is escaped a second time
        // and the client renders `&amp;quot;`.
        assert_eq!(html_escape(r#"&""#), "&amp;&quot;");
    }

    #[test]
    fn urlencoding_leaves_the_unreserved_set_alone() {
        assert_eq!(urlencoded("a-z_0.9~"), "a-z_0.9~");
        assert_eq!(urlencoded("New user & PC"), "New%20user%20%26%20PC");
    }

    #[test]
    fn page_shell_css_shares_font_and_margin_across_max_widths() {
        let narrow = page_shell_css("36rem");
        let wide = page_shell_css("64rem");
        assert!(narrow.contains("font-family:system-ui,-apple-system,sans-serif"));
        assert!(wide.contains("font-family:system-ui,-apple-system,sans-serif"));
        assert!(narrow.contains("margin:2rem auto"));
        assert!(wide.contains("margin:2rem auto"));
        assert!(narrow.contains("max-width:36rem"));
        assert!(wide.contains("max-width:64rem"));
        assert!(narrow.contains("color-scheme:light dark"));
    }
}
