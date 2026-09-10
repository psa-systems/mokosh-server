//! HTML renderer for [`super::ProviderStatusReport`].
//!
//! Self-contained static markup: no JavaScript, no external assets, no
//! templating engine. Every inserted value is HTML-escaped through
//! [`crate::utils::html::html_escape`], the same helper the tenant logo mail
//! and the `not_a_frontend` page already use, so the escape rules stay in
//! one place. The `<meta name="robots" content="noindex">` line is there
//! because a standalone deployment can bookmark this URL and the page must
//! not be crawled.

use crate::utils::html::html_escape;

use super::{KindEnumerationStatus, ProviderStatusReport};

/// Render the report as a whole HTML page. The tests in
/// `super::tests::html_*` pin the shape (a title, one `<section>` per kind,
/// escaped dynamic values).
pub fn render_html(report: &ProviderStatusReport) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("<!doctype html>\n<html lang=\"en\"><head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"robots\" content=\"noindex\">\n");
    out.push_str("<title>Mokosh Provider Status</title>\n");
    out.push_str("<style>");
    out.push_str(include_str!("style.css"));
    out.push_str("</style>\n</head><body>\n");
    out.push_str("<h1>Mokosh Provider Status</h1>\n");

    // -- Overview --------------------------------------------------------
    out.push_str("<section id=\"overview\">\n<h2>Overview</h2>\n<dl>\n");
    push_kv(&mut out, "Hosting profile", report.hosting_profile);
    push_kv(
        &mut out,
        "Generation number",
        &report.configuration_generation.number.to_string(),
    );
    push_kv(
        &mut out,
        "Resolved at",
        &report.configuration_generation.resolved_at.to_rfc3339(),
    );
    push_kv(&mut out, "Actor", &report.configuration_generation.actor);
    push_kv(&mut out, "Collected at", &report.collected_at.to_rfc3339());
    out.push_str("</dl>\n");

    // -- Deviations ------------------------------------------------------
    if report.deviations.is_empty() {
        out.push_str("<p class=\"muted\">No hosting-profile deviations.</p>\n");
    } else {
        out.push_str("<h3>Deviations</h3>\n<table>\n");
        out.push_str(
            "<thead><tr><th>Kind</th><th>Profile default</th><th>Explicit</th></tr></thead>\n<tbody>\n",
        );
        for deviation in &report.deviations {
            out.push_str("<tr>");
            push_td(&mut out, deviation.kind);
            push_td(&mut out, &deviation.profile_default.join(", "));
            push_td(&mut out, &deviation.explicit.join(", "));
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table>\n");
    }
    out.push_str("</section>\n");

    // -- Kinds ----------------------------------------------------------
    for kind in &report.kinds {
        out.push_str(&format!("<section id=\"{}\">\n", html_escape(kind.kind)));
        out.push_str(&format!("<h2>{}</h2>\n", html_escape(kind.kind)));
        if let Some(name) = kind.serving {
            out.push_str(&format!(
                "<p><strong>Serving:</strong> {}</p>\n",
                html_escape(name)
            ));
        } else {
            out.push_str("<p class=\"muted\"><strong>Serving:</strong> none</p>\n");
        }

        if !kind.enabled.is_empty() {
            out.push_str("<h3>Enabled providers</h3>\n<table>\n");
            out.push_str(
                "<thead><tr><th>Name</th><th>Priority</th><th>Reachable</th><th>Note</th></tr></thead>\n<tbody>\n",
            );
            for enabled in &kind.enabled {
                out.push_str("<tr>");
                push_td(&mut out, enabled.name);
                push_td(&mut out, &enabled.priority.to_string());
                push_td(&mut out, if enabled.reachable { "yes" } else { "no" });
                push_td(
                    &mut out,
                    enabled.unreachable_reason.as_deref().unwrap_or(""),
                );
                out.push_str("</tr>\n");
            }
            out.push_str("</tbody></table>\n");
        }

        if !kind.keys.is_empty() {
            out.push_str("<h3>Keys</h3>\n<table>\n");
            out.push_str(
                "<thead><tr><th>Key</th><th>Feature</th><th>Recorded served by</th><th>Live holds</th><th>State</th></tr></thead>\n<tbody>\n",
            );
            for key in &kind.keys {
                out.push_str("<tr>");
                push_td(&mut out, key.key);
                push_td(&mut out, key.feature.unwrap_or(""));
                push_td(&mut out, key.recorded_served_by.unwrap_or(""));
                push_td(&mut out, if key.live_holds { "yes" } else { "no" });
                push_state_td(&mut out, key.state);
                out.push_str("</tr>\n");
            }
            out.push_str("</tbody></table>\n");
        }

        match &kind.enumeration {
            None => {}
            Some(KindEnumerationStatus::Unsupported) => {
                out.push_str(
                    "<p class=\"muted\">Enumeration: unsupported (the provider does not list its contents).</p>\n",
                );
            }
            Some(KindEnumerationStatus::Supported(names)) => {
                out.push_str(&format!(
                    "<p><strong>Enumeration:</strong> {} keys.</p>\n",
                    names.len()
                ));
            }
        }

        out.push_str("</section>\n");
    }

    out.push_str("</body></html>\n");
    out
}

fn push_kv(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!(
        "<dt>{}</dt><dd>{}</dd>\n",
        html_escape(label),
        html_escape(value)
    ));
}

fn push_td(out: &mut String, value: &str) {
    out.push_str(&format!("<td>{}</td>", html_escape(value)));
}

fn push_state_td(out: &mut String, state: &str) {
    // Colour-code divergence: unchanged is quiet, any other state is loud.
    let class = if state == "unchanged" {
        "state-unchanged"
    } else {
        "state-diverged"
    };
    out.push_str(&format!(
        "<td class=\"{}\">{}</td>",
        html_escape(class),
        html_escape(state)
    ));
}
