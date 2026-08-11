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
}
