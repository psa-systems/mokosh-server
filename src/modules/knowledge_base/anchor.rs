//! The shape of an inline comment's anchor (PMS-1130).
//!
//! An anchor is a W3C Web Annotation selector over the RENDERED text of the
//! article: the quoted text itself, up to 64 characters either side of it,
//! and a positional hint. The server validates the shape on `POST` and
//! never interprets it: resolving an anchor against the article, and
//! deciding that one no longer resolves (an orphan), is the client's job on
//! render, because it is the only party holding the rendered text. The
//! stored value is the JSON as given, so what the client wrote is what it
//! reads back, byte for byte; only the shape is checked, and a shape the
//! client did not mean is a 422 naming the field rather than a row that
//! will never resolve.
//!
//! ```json
//! { "type": "TextQuoteSelector", "exact": "...", "prefix": "...", "suffix": "...",
//!   "refinedBy": { "type": "TextPositionSelector", "start": 1234, "end": 1251 } }
//! ```
//!
//! Strict on purpose: an unknown key at either level is refused, because the
//! only writer is our own client and a misspelt key there is a bug to
//! surface, not data to keep.
//!
//! One thing the server DOES change, and not here: every JSON body passes
//! through `utils::text::sanitize_json_body` (PMS-924) before any handler,
//! which trims every string at every depth. So `prefix` and `suffix` arrive
//! trimmed, and a context that was only whitespace (a quote at a paragraph
//! boundary) arrives empty. The client's resolver compares trimmed context
//! for that reason; `exact` is trimmed the same way, and a quote that begins
//! or ends in whitespace is matched without it.

use serde::Deserialize;

use crate::utils::error::{AppError, AppResult};

/// The quote may be long (a paragraph), the context is deliberately short:
/// it disambiguates, it does not re-quote.
pub const EXACT_MAX: usize = 2000;
pub const CONTEXT_MAX: usize = 64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextQuoteSelector {
    #[serde(rename = "type")]
    kind: String,
    exact: String,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    suffix: Option<String>,
    #[serde(default, rename = "refinedBy")]
    refined_by: Option<TextPositionSelector>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextPositionSelector {
    #[serde(rename = "type")]
    kind: String,
    start: i64,
    end: i64,
}

/// Refuse an anchor whose shape the client cannot have meant. `Ok` says
/// nothing about whether it resolves.
pub fn validate(anchor: &serde_json::Value) -> AppResult<()> {
    let selector: TextQuoteSelector = serde_json::from_value(anchor.clone()).map_err(|e| {
        AppError::validation_field("anchor", format!("not a TextQuoteSelector: {e}"))
    })?;
    if selector.kind != "TextQuoteSelector" {
        return Err(AppError::validation_field(
            "anchor.type",
            "must be TextQuoteSelector",
        ));
    }
    let exact_len = selector.exact.chars().count();
    if exact_len == 0 {
        return Err(AppError::validation_field(
            "anchor.exact",
            "the quoted text is required",
        ));
    }
    if exact_len > EXACT_MAX {
        return Err(AppError::validation_field(
            "anchor.exact",
            format!("the quoted text is longer than {EXACT_MAX} characters"),
        ));
    }
    for (field, value) in [
        ("anchor.prefix", &selector.prefix),
        ("anchor.suffix", &selector.suffix),
    ] {
        if value
            .as_ref()
            .is_some_and(|v| v.chars().count() > CONTEXT_MAX)
        {
            return Err(AppError::validation_field(
                field,
                format!("context is longer than {CONTEXT_MAX} characters"),
            ));
        }
    }
    if let Some(position) = selector.refined_by {
        if position.kind != "TextPositionSelector" {
            return Err(AppError::validation_field(
                "anchor.refinedBy.type",
                "must be TextPositionSelector",
            ));
        }
        if position.start < 0 {
            return Err(AppError::validation_field(
                "anchor.refinedBy.start",
                "must not be negative",
            ));
        }
        if position.end < position.start {
            return Err(AppError::validation_field(
                "anchor.refinedBy.end",
                "must not be before start",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The field the refusal names, which is what the 422 body carries.
    fn field(result: AppResult<()>) -> String {
        match result {
            Err(AppError::Validation { errors, .. }) => {
                errors.first().map(|f| f.field.clone()).unwrap_or_default()
            }
            Err(other) => format!("not a validation error: {other}"),
            Ok(()) => "ok".to_string(),
        }
    }

    #[test]
    fn a_full_selector_and_a_bare_quote_both_pass() {
        assert!(validate(&json!({
            "type": "TextQuoteSelector", "exact": "Restart the router", "prefix": "before ", "suffix": " after",
            "refinedBy": { "type": "TextPositionSelector", "start": 10, "end": 28 }
        }))
        .is_ok());
        assert!(validate(&json!({ "type": "TextQuoteSelector", "exact": "x" })).is_ok());
        assert!(
            validate(&json!({
                "type": "TextQuoteSelector", "exact": "x",
                "refinedBy": { "type": "TextPositionSelector", "start": 3, "end": 3 }
            }))
            .is_ok(),
            "an empty range is a position"
        );
    }

    #[test]
    fn each_rule_names_its_field() {
        let cases = [
            (json!({ "exact": "x" }), "anchor"),
            (
                json!({ "type": "RangeSelector", "exact": "x" }),
                "anchor.type",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "" }),
                "anchor.exact",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "x".repeat(EXACT_MAX + 1) }),
                "anchor.exact",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "x", "prefix": "p".repeat(CONTEXT_MAX + 1) }),
                "anchor.prefix",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "x", "suffix": "s".repeat(CONTEXT_MAX + 1) }),
                "anchor.suffix",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "x", "refinedBy": { "type": "Other", "start": 0, "end": 1 } }),
                "anchor.refinedBy.type",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "x", "refinedBy": { "type": "TextPositionSelector", "start": -1, "end": 1 } }),
                "anchor.refinedBy.start",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "x", "refinedBy": { "type": "TextPositionSelector", "start": 5, "end": 4 } }),
                "anchor.refinedBy.end",
            ),
            (
                json!({ "type": "TextQuoteSelector", "exact": "x", "colour": "red" }),
                "anchor",
            ),
            (json!("just a string"), "anchor"),
        ];
        for (anchor, expected) in cases {
            let msg = field(validate(&anchor));
            assert!(
                msg.contains(expected),
                "{anchor} -> {msg}, expected {expected}"
            );
        }
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        let exact: String = "é".repeat(EXACT_MAX);
        assert!(validate(&json!({ "type": "TextQuoteSelector", "exact": exact })).is_ok());
    }
}
