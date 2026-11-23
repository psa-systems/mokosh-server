//! Branded wrapper for outbound mail bodies.
//!
//! Applied at dispatch, not at template-save time, so a stored body stays the
//! operator's text and a layout change reaches already-queued rows.

use std::sync::OnceLock;

use minijinja::{context, Environment};

fn env() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        // Compile-time embedding: no runtime file discovery on the send path.
        for (name, src) in [
            (
                "base.html",
                include_str!("../../templates/emails/base.html"),
            ),
            ("base.txt", include_str!("../../templates/emails/base.txt")),
            (
                "wrapped.html",
                include_str!("../../templates/emails/wrapped.html"),
            ),
            (
                "wrapped.txt",
                include_str!("../../templates/emails/wrapped.txt"),
            ),
        ] {
            env.add_template(name, src)
                .expect("embedded email template must parse");
        }
        env
    })
}

fn render(name: &str, subject: &str, content: &str) -> String {
    env()
        .get_template(name)
        .and_then(|t| t.render(context! { subject, content }))
        // A broken layout must never block mail: fall back to the bare body.
        .unwrap_or_else(|e| {
            tracing::warn!(target: "mokosh_server.mailer", error = %e, template = name, "email layout failed; sending unwrapped");
            content.to_string()
        })
}

/// Wrap an HTML body in the branded card. `content` is trusted, already-escaped HTML.
pub fn wrap_html(subject: &str, content: &str) -> String {
    render("wrapped.html", subject, content)
}

/// Wrap a plain-text body with the shared footer.
pub fn wrap_text(subject: &str, content: &str) -> String {
    render("wrapped.txt", subject, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_layout_carries_the_wordmark_and_the_unescaped_body() {
        let out = wrap_html("Hi", "<p>Hello <b>there</b></p>");
        assert!(out.contains("Mokosh"));
        assert!(out.contains("<p>Hello <b>there</b></p>"));
        assert!(out.contains("<title>Hi</title>"));
    }

    #[test]
    fn text_layout_keeps_the_body_and_adds_the_footer() {
        let out = wrap_text("Hi", "Hello & welcome");
        assert!(out.contains("Hello & welcome"));
        assert!(out.contains("Sent by Mokosh"));
    }
}
