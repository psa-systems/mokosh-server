//! KB article rendering: minijinja with the default `{{ }}` / `{% %}`
//! delimiters, Lenient undefined so a missing variable takes the else
//! branch of a conditional, and a bare `{{ name }}` whose variable has
//! no value renders as a visible `[missing: NAME]` placeholder.
//!
//! A render never returns 500: a template that fails to parse or a
//! render that fails inside the engine comes back as
//! [`AppError::BadRequest`] with the engine's message, so the editor
//! can show the author what their template did wrong without taking
//! the article's whole page down.

use std::collections::BTreeMap;

use minijinja::{Environment, UndefinedBehavior, Value};

use crate::utils::error::{AppError, AppResult};

use super::models::KbTemplateVariable;

/// Render `content` with the caller-supplied `values` map, declared
/// variables and all. Short-circuits when both the declared schema and
/// the values map are empty: the stored Markdown is returned byte-
/// identically, with no engine pass. This is the "an article with no
/// declared variables and no values renders unchanged" contract.
pub fn render_article(
    content: &str,
    declared: &[KbTemplateVariable],
    values: &BTreeMap<String, String>,
) -> AppResult<String> {
    // An article that declares no variables renders byte-identically
    // to its stored content: the engine is skipped entirely so a `{{`
    // or `{%` sequence that happens to live in the stored Markdown is
    // not treated as a template.
    if declared.is_empty() {
        return Ok(content.to_string());
    }

    // Fold the declared defaults in BEFORE the caller's values so an
    // explicit value wins. A declared variable with no default stays
    // absent, and resolves per the Lenient / preprocessing rules below.
    let mut resolved: BTreeMap<&str, String> = BTreeMap::new();
    for var in declared {
        if let Some(default) = &var.default {
            resolved.insert(var.name.as_str(), default.clone());
        }
    }
    for (name, value) in values {
        resolved.insert(name.as_str(), value.clone());
    }

    // Walk every `{{ ... }}` block and, where the block is a bare
    // identifier naming a DECLARED variable that has no resolved
    // value, rewrite the block to the `[missing: NAME]` placeholder.
    // Non-declared identifiers (loop variables, future globals) are
    // left alone, because the engine owns their scope. `{% ... %}`
    // blocks are also untouched: Lenient undefined makes a bare
    // `{% if NAME %}` fall to the else branch when the name has no
    // value, which is the conditional contract.
    let declared_names: std::collections::HashSet<&str> =
        declared.iter().map(|v| v.name.as_str()).collect();
    let prepared = substitute_missing_placeholders(content, |name| {
        declared_names.contains(name) && !resolved.contains_key(name)
    });

    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Lenient);
    // One-off template, so no name is reused on cache lookups. `render_str`
    // compiles once and discards; the engine is cheap enough that the KB
    // page's single-call latency stays well under its sanitize cost anyway.
    let ctx: BTreeMap<&str, Value> = resolved
        .iter()
        .map(|(name, value)| (*name, Value::from(value.clone())))
        .collect();
    env.render_str(&prepared, ctx)
        .map_err(|err| AppError::BadRequest(format!("Template render failed: {err}.")))
}

/// Scan `template` for `{{ ... }}` blocks whose body is a bare identifier
/// `is_missing` says is absent, and replace each with `[missing: NAME]`.
/// Everything else is passed through byte-identically, so a template with
/// no bare-identifier substitutions comes back unchanged.
fn substitute_missing_placeholders(template: &str, is_missing: impl Fn(&str) -> bool) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            // Unclosed `{{` falls through to the engine, which will
            // return a parse error the caller surfaces as 400.
            out.push_str("{{");
            out.push_str(after);
            return out;
        };
        let inner = &after[..end];
        let trimmed = inner.trim();
        if is_bare_identifier(trimmed) && is_missing(trimmed) {
            out.push_str("[missing: ");
            out.push_str(trimmed);
            out.push(']');
        } else {
            out.push_str("{{");
            out.push_str(inner);
            out.push_str("}}");
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// A bare template identifier: a non-empty run of ASCII letters, digits
/// and underscores starting with a letter or underscore. Anything with a
/// dot, pipe, parenthesis or operator falls through unchanged, so a
/// template like `{{ user.name | upper }}` is left for the engine.
fn is_bare_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_text(name: &str) -> KbTemplateVariable {
        KbTemplateVariable {
            name: name.to_string(),
            label: name.to_string(),
            allowed_values: vec![],
            default: None,
        }
    }

    fn vars() -> Vec<KbTemplateVariable> {
        vec![
            free_text("host"),
            KbTemplateVariable {
                name: "environment".to_string(),
                label: "Environment".to_string(),
                allowed_values: vec!["staging".into(), "production".into()],
                default: Some("staging".into()),
            },
        ]
    }

    #[test]
    fn no_declared_variables_short_circuits_byte_identically() {
        let out =
            render_article("# Title\n\n{{ not_rendered }}", &[], &BTreeMap::new()).expect("render");
        assert_eq!(out, "# Title\n\n{{ not_rendered }}");
    }

    #[test]
    fn declared_default_is_used_when_caller_passes_no_value() {
        let out =
            render_article("env={{ environment }}", &vars(), &BTreeMap::new()).expect("render");
        assert_eq!(out, "env=staging");
    }

    #[test]
    fn caller_value_overrides_declared_default() {
        let mut v = BTreeMap::new();
        v.insert("environment".to_string(), "production".to_string());
        let out = render_article("env={{ environment }}", &vars(), &v).expect("render");
        assert_eq!(out, "env=production");
    }

    #[test]
    fn undefined_var_in_conditional_takes_else_branch() {
        // `environment` is declared (no default) and no caller value;
        // Lenient undefined makes the equality false, so else is taken.
        let out = render_article(
            "{% if environment == \"production\" %}P{% else %}S{% endif %}",
            &[free_text("environment")],
            &BTreeMap::new(),
        )
        .expect("render");
        assert_eq!(out, "S");
    }

    #[test]
    fn undefined_bare_var_renders_missing_placeholder() {
        let out = render_article("host={{ host }}", &[free_text("host")], &BTreeMap::new())
            .expect("render");
        assert_eq!(out, "host=[missing: host]");
    }

    #[test]
    fn for_loop_with_split_filter_handles_csv_values() {
        // A list-shaped variable value is CSV-encoded by the caller; a
        // real `for` loop needs structured input which Phase 1a does
        // not take. This test pins minijinja's default `for` + the
        // `split` filter working on a free-text declared variable.
        let mut v = BTreeMap::new();
        v.insert("items".to_string(), "a,b,c".to_string());
        let out = render_article(
            "{% for item in items | split(\",\") %}{{ item }} {% endfor %}",
            &[free_text("items")],
            &v,
        )
        .expect("render");
        assert_eq!(out, "a b c ");
    }

    #[test]
    fn complex_expression_with_undefined_is_not_substituted() {
        // Our substitution only fires on a bare identifier; `{{ x|upper }}`
        // with x undefined is left for the engine. Lenient undefined
        // then renders it as empty rather than erroring.
        let out =
            render_article("v={{ x|upper }}", &[free_text("x")], &BTreeMap::new()).expect("render");
        assert_eq!(out, "v=");
    }
}
