//! Outbound email for the auth subsystem.
//!
//! `Mailer` is the trait every `send_*` callsite uses. Production
//! environments wire `LettreMailer` (real SMTP). Dev environments use
//! `LogMailer`, which writes the link to `tracing` so smoke tests work
//! without an SMTP server. Tests use `RecordingMailer` (kept private to
//! the test module that needs it).

use async_trait::async_trait;
use mokosh_auth_core::{AuthError, Invite, User};

#[async_trait]
pub trait Mailer: Send + Sync {
    /// Send the invite email. `raw_token` is the unhashed token; the
    /// impl interpolates it into the link.
    async fn send_invite(
        &self,
        invite: &Invite,
        raw_token: &str,
        inviter: &User,
    ) -> Result<(), AuthError>;
}

/// Dev-only mailer. Logs the would-be email body to `tracing` and
/// returns Ok. Never use in production.
pub struct LogMailer {
    pub accept_base_url: String,
}

#[async_trait]
impl Mailer for LogMailer {
    async fn send_invite(
        &self,
        invite: &Invite,
        raw_token: &str,
        inviter: &User,
    ) -> Result<(), AuthError> {
        let link = format!(
            "{}/invite/{}",
            self.accept_base_url.trim_end_matches('/'),
            raw_token,
        );
        tracing::info!(
            target: "mokosh_auth.mailer",
            to = %invite.email,
            inviter = %inviter.email,
            role = %invite.role.as_str(),
            link = %link,
            "[DEV] would send invite email"
        );
        Ok(())
    }
}

/// HTML-escape user-controlled strings before rendering them in email
/// bodies. Same helper as the login-form renderer; lift to a shared
/// module if a third caller arrives.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Display-name for the inviter, falling back to email if no name set.
pub fn display_name(u: &User) -> String {
    match (&u.first_name, &u.last_name) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        (Some(f), None) => f.clone(),
        (None, Some(l)) => l.clone(),
        _ => u.email.clone(),
    }
}
