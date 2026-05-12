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

    /// Send a self-signup confirmation email. The recipient clicks
    /// the link and lands on /signup/<raw_token>, where they pick a
    /// password and finish creating the account. We deliberately
    /// send no payload other than the link itself: the body is
    /// identical for "new email" and "email already in use" cases
    /// so the recipient cannot infer enumeration outcomes from the
    /// message.
    async fn send_signup(&self, email: &str, raw_token: &str) -> Result<(), AuthError>;
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

    async fn send_signup(&self, email: &str, raw_token: &str) -> Result<(), AuthError> {
        let link = format!(
            "{}/signup/{}",
            self.accept_base_url.trim_end_matches('/'),
            raw_token,
        );
        tracing::info!(
            target: "mokosh_auth.mailer",
            to = %email,
            link = %link,
            "[DEV] would send signup email"
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

// --- LettreMailer (real SMTP) ------------------------------------------
//
// Talks SMTP to a configured relay (Amazon SES, Postmark, SendGrid,
// self-hosted, or mailpit in dev). Selected at bootstrap when
// SMTP_HOST is set; LogMailer otherwise. See
// docs/mokosh-smtp/02-lettre-mailer.md for the design and
// docs/mokosh-smtp/03-config-and-bootstrap.md for the env contract.
//
// Bodies are placeholder text-only for phase 2; phase 4 lands the
// proper text + HTML templates.

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// TLS mode for the SMTP submission connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Plaintext SMTP. Use ONLY against mailpit (dev) or behind a
    /// trusted in-network relay. Real relays MUST use StartTls or
    /// ImplicitTls.
    None,
    /// Plain TCP, upgrade to TLS via STARTTLS. Standard for port 587.
    StartTls,
    /// TLS from the first byte. Standard for port 465.
    ImplicitTls,
}

impl TlsMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsMode::None => "none",
            TlsMode::StartTls => "starttls",
            TlsMode::ImplicitTls => "implicit",
        }
    }
}

/// Inputs `LettreMailer::new` needs to build a transport. Constructed
/// at bootstrap from `SMTP_*` env vars; never read env vars from
/// inside the mailer itself.
pub struct LettreConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// RFC 5322 mailbox, e.g. `Mokosh <noreply@example.com>`. Parsed
    /// up-front so a typo at deploy time fails the boot rather than
    /// the first send.
    pub from: String,
    pub tls: TlsMode,
    /// Same `accept_base_url` LogMailer uses: prefix for the
    /// /invite/<token> and /signup/<token> links in the body.
    pub accept_base_url: String,
}

/// Real-SMTP `Mailer` impl. Wraps an `AsyncSmtpTransport` (lettre's
/// connection-pooled async client). Cheap to clone; the underlying
/// transport is Arc'd internally.
pub struct LettreMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    accept_base_url: String,
}

impl LettreMailer {
    /// Build a mailer from validated configuration. Fails fast when
    /// `from` does not parse as an RFC 5322 mailbox; we want the
    /// error at boot, not on the first send.
    pub fn new(cfg: LettreConfig) -> Result<Self, AuthError> {
        let from = cfg
            .from
            .parse::<Mailbox>()
            .map_err(|e| AuthError::Internal(format!("SMTP_FROM is not a valid mailbox: {e}")))?;

        // Builder per TLS mode. lettre's relay() = implicit TLS,
        // starttls_relay() = STARTTLS, builder_dangerous() = plaintext.
        let builder = match cfg.tls {
            TlsMode::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host),
            TlsMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                .map_err(|e| AuthError::Internal(format!("SMTP STARTTLS relay: {e}")))?,
            TlsMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
                .map_err(|e| AuthError::Internal(format!("SMTP implicit-TLS relay: {e}")))?,
        };
        let mut builder = builder.port(cfg.port);

        // PLAIN auth when credentials are present. mailpit and some
        // in-network relays accept anonymous; skip auth in that case.
        if let (Some(u), Some(p)) = (cfg.username.as_deref(), cfg.password.as_deref()) {
            if !u.is_empty() {
                builder = builder.credentials(Credentials::new(u.into(), p.into()));
            }
        }

        Ok(Self {
            transport: builder.build(),
            from,
            accept_base_url: cfg.accept_base_url,
        })
    }

    fn build_link(&self, segment: &str, raw_token: &str) -> String {
        format!(
            "{}/{}/{}",
            self.accept_base_url.trim_end_matches('/'),
            segment.trim_matches('/'),
            raw_token,
        )
    }

    /// Compose + submit a single message. Phase 2 stays with
    /// text/plain only; phase 4 (templates) swaps in
    /// multipart/alternative with HTML.
    async fn send_text(&self, to: Mailbox, subject: &str, text: String) -> Result<(), AuthError> {
        let msg = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .body(text)
            .map_err(|e| AuthError::Internal(format!("compose: {e}")))?;
        self.transport
            .send(msg)
            .await
            .map_err(|e| AuthError::Internal(format!("smtp send: {e}")))?;
        Ok(())
    }
}

fn parse_recipient(addr: &str) -> Result<Mailbox, AuthError> {
    addr.trim()
        .parse::<Mailbox>()
        .map_err(|e| AuthError::Internal(format!("recipient '{addr}' is not a valid mailbox: {e}")))
}

#[async_trait]
impl Mailer for LettreMailer {
    async fn send_invite(
        &self,
        invite: &Invite,
        raw_token: &str,
        inviter: &User,
    ) -> Result<(), AuthError> {
        let link = self.build_link("invite", raw_token);
        let to = parse_recipient(&invite.email)?;
        let subject = "You're invited to Mokosh".to_string();
        let body = format!(
            "Hi,\n\n\
             {} ({}) invited you to join Mokosh as {}.\n\n\
             Accept the invite by clicking this link within 7 days:\n\n  {}\n\n\
             If you did not expect this invite, you can safely ignore this email.\n\n\
             (This is an automated message; do not reply.)\n",
            display_name(inviter),
            inviter.email,
            invite.role.as_str(),
            link,
        );
        self.send_text(to, &subject, body).await
    }

    async fn send_signup(&self, email: &str, raw_token: &str) -> Result<(), AuthError> {
        let link = self.build_link("signup", raw_token);
        let to = parse_recipient(email)?;
        let subject = "Confirm your Mokosh account".to_string();
        let body = format!(
            "Hi,\n\n\
             A Mokosh account creation was requested for {}. Click the link\n\
             below to set a password and finish creating the account. The link\n\
             is valid for 24 hours and can only be used once.\n\n  {}\n\n\
             If you did not request this, you can safely ignore this email;\n\
             nothing will happen and no account will be created.\n\n\
             (This is an automated message; do not reply.)\n",
            email, link,
        );
        self.send_text(to, &subject, body).await
    }
}
