//! GFM task-list parser for KB article executions.
//!
//! Scans rendered Markdown line-by-line and returns one `ParsedStep`
//! per task-list item it finds. The two accepted shapes are the
//! unordered `- [ ] text` / `- [x] text` and the ordered
//! `1. [ ] text` / `1. [x] text` (any digit run before the dot). The
//! `x` is case-insensitive. Any other line is not a step.
//!
//! A fenced code block (``` or ~~~) is tracked and its contents are
//! skipped, so a code example that happens to contain `- [ ] foo`
//! does not become a step. Leading whitespace on a list marker is
//! allowed (markdown's "lists can nest under lists" rule): a nested
//! `  - [ ] text` under an outer list item still counts, with its
//! `index` taken from the full flattened scan.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStep {
    /// 0-based ordinal in the rendered content.
    pub index: i32,
    /// Checkbox contents at parse time: `true` for `[x]` / `[X]`.
    pub initially_checked: bool,
    /// The text after the checkbox, trimmed.
    pub text: String,
}

/// Scan `rendered` for GFM task-list items; see module docs for the
/// shapes accepted. Fenced code blocks are tracked and skipped.
pub fn parse_steps(rendered: &str) -> Vec<ParsedStep> {
    let mut out = Vec::new();
    let mut in_fence = false;
    let mut fence_marker: Option<char> = None;
    let mut index: i32 = 0;

    for line in rendered.split('\n') {
        let trimmed = line.trim_start();
        // Fence toggling: a line whose non-whitespace prefix is three or
        // more of the same marker (``` or ~~~) opens or closes a fence.
        if let Some(marker) = fence_marker_of(trimmed) {
            match fence_marker {
                Some(existing) if existing == marker => {
                    in_fence = false;
                    fence_marker = None;
                }
                None => {
                    in_fence = true;
                    fence_marker = Some(marker);
                }
                _ => {}
            }
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(step) = parse_task_line(trimmed, index) {
            out.push(step);
            index += 1;
        }
    }

    out
}

/// Return the fence marker character of a line that opens or closes a
/// fenced code block, or `None` for any other line. A fence is a run
/// of three or more identical backticks or tildes; anything after the
/// run (an info string like "```rust") is allowed.
fn fence_marker_of(trimmed: &str) -> Option<char> {
    let marker = trimmed.chars().next()?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run = trimmed.chars().take_while(|c| *c == marker).count();
    if run >= 3 {
        Some(marker)
    } else {
        None
    }
}

/// Parse a trimmed line as a task-list item. Returns `None` if the
/// line is not a task-list item in either the unordered or ordered
/// shape.
fn parse_task_line(trimmed: &str, index: i32) -> Option<ParsedStep> {
    // Unordered: `- `, `* `, or `+ ` as the marker. GFM accepts all
    // three for bullets; the Phase 2a spec names `-`, but accepting
    // the sibling bullets costs nothing and matches what most editors
    // produce when the author pressed Enter inside an existing list.
    let after_marker = if let Some(rest) = trimmed.strip_prefix("- ") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("* ") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("+ ") {
        rest
    } else {
        // Ordered: a run of ASCII digits, then `. ` or `) ` and the
        // task-list body. Anything else is not a step.
        strip_ordered_marker(trimmed)?
    };

    let (checked, body) = strip_checkbox(after_marker)?;
    Some(ParsedStep {
        index,
        initially_checked: checked,
        text: body.trim().to_string(),
    })
}

/// Strip a `1. ` / `12) ` style ordered-list marker and return the
/// remainder; returns `None` if the line does not begin with a digit
/// run followed by a `.` or `)` and a space.
fn strip_ordered_marker(trimmed: &str) -> Option<&str> {
    let digits: usize = trimmed.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let after_digits = &trimmed[digits..];
    let rest = after_digits
        .strip_prefix(". ")
        .or_else(|| after_digits.strip_prefix(") "))?;
    Some(rest)
}

/// Strip the `[ ]` or `[x]` / `[X]` checkbox, returning
/// `(initially_checked, remainder)`. Returns `None` if the line does
/// not start with a well-formed checkbox token.
fn strip_checkbox(after_marker: &str) -> Option<(bool, &str)> {
    let bytes = after_marker.as_bytes();
    if bytes.len() < 3 || bytes[0] != b'[' || bytes[2] != b']' {
        return None;
    }
    let inside = bytes[1];
    let checked = match inside {
        b' ' => false,
        b'x' | b'X' => true,
        _ => return None,
    };
    // The checkbox is followed by a space before the body; a bare
    // `[x]` with no trailing text is still a step (empty body).
    let after = &after_marker[3..];
    let body = after.strip_prefix(' ').unwrap_or(after);
    Some((checked, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_dash_steps() {
        let steps = parse_steps("- [ ] First\n- [ ] Second\n");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].index, 0);
        assert_eq!(steps[0].text, "First");
        assert!(!steps[0].initially_checked);
        assert_eq!(steps[1].index, 1);
        assert_eq!(steps[1].text, "Second");
    }

    #[test]
    fn prose_has_zero_steps() {
        let steps =
            parse_steps("# Title\n\nSome prose that mentions - [ ] in the middle of a sentence.\n");
        assert_eq!(steps.len(), 0);
    }

    #[test]
    fn nested_task_items_count_with_flattened_ordinal() {
        let steps = parse_steps(
            "- [ ] Outer step\n  - [ ] Nested step\n  - [x] Already done nested\n- [ ] Last\n",
        );
        assert_eq!(steps.len(), 4);
        assert_eq!(steps[0].text, "Outer step");
        assert_eq!(steps[1].text, "Nested step");
        assert_eq!(steps[2].text, "Already done nested");
        assert!(steps[2].initially_checked);
        assert_eq!(steps[3].index, 3);
    }

    #[test]
    fn fenced_code_block_contents_are_not_steps() {
        let src = "- [ ] Before\n```\n- [ ] Inside\n- [x] Inside too\n```\n- [ ] After\n";
        let steps = parse_steps(src);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].text, "Before");
        assert_eq!(steps[1].text, "After");
        assert_eq!(steps[1].index, 1);
    }

    #[test]
    fn tilde_fence_also_skipped() {
        let src = "~~~\n- [ ] Hidden\n~~~\n- [ ] Visible\n";
        let steps = parse_steps(src);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].text, "Visible");
    }

    #[test]
    fn ordered_list_task_items_count() {
        let src = "1. [ ] One\n2. [x] Two\n";
        let steps = parse_steps(src);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].text, "One");
        assert!(steps[1].initially_checked);
    }

    #[test]
    fn x_is_case_insensitive() {
        let src = "- [X] Capital X\n- [x] Lower x\n";
        let steps = parse_steps(src);
        assert_eq!(steps.len(), 2);
        assert!(steps[0].initially_checked);
        assert!(steps[1].initially_checked);
    }

    #[test]
    fn unterminated_fence_swallows_rest_of_doc() {
        // Author forgot to close the fence: nothing after the opening
        // marker is a step. This is the GFM reader's own behaviour.
        let src = "- [ ] Before\n```\n- [ ] Inside no close\n";
        let steps = parse_steps(src);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].text, "Before");
    }
}
