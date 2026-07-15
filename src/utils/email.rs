//! Outbound email for the PSA host crate.
//!
//! `Mailer` is the trait every auth/notifications callsite uses.
//! `LogMailer` (dev) records the would-be link in tracing; `SmtpMailer`
//! (prod / dev with SMTP_HOST set) drives lettre.
//!
//! The same SMTP_* env vars documented in .env.example are honoured.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lettre::message::{Mailbox, MessageBuilder, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};

/// Anything that can send mokosh's transactional emails.
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Password reset link mail. `reset_link` is the full URL the user
    /// clicks (token already interpolated).
    async fn send_password_reset(&self, to: &str, reset_link: &str) -> AppResult<()>;

    /// Welcome / account-created mail for users provisioned by an
    /// admin. `setup_link` lands them on a "pick your password" page.
    async fn send_welcome(&self, to: &str, display_name: &str, setup_link: &str) -> AppResult<()>;

    /// Generic plain-text mail. Escape hatch for notification flows
    /// that don't fit a typed helper above (e.g. ticket-note
    /// notifications, ad-hoc alerts). Prefer a typed helper when adding
    /// a recurring template; reserve this for one-off bodies.
    async fn send_text(&self, to: &str, subject: &str, body: &str) -> AppResult<()>;

    /// PMS-657: alert the user that a sign-in came from a country they have not
    /// signed in from before. The default composes a plain-text body and routes
    /// it through [`Mailer::send_text`], so every mailer inherits it without a
    /// per-impl override.
    async fn send_new_login_location(
        &self,
        to: &str,
        country: &str,
        ip: &str,
        when: &str,
        user_agent: &str,
        security_link: &str,
    ) -> AppResult<()> {
        let body = format!(
            "We noticed a sign-in to your account from a country we have not seen you sign in from before.\n\n\
             Country: {country}\n\
             IP address: {ip}\n\
             When: {when}\n\
             Device: {user_agent}\n\n\
             If this was you, no action is needed.\n\n\
             If you do not recognize this sign-in, secure your account now: review your active sessions and change your password.\n\n\
             {security_link}"
        );
        self.send_text(to, "New sign-in to your account", &body)
            .await
    }

    /// PMS-658: email a single-use code to approve a suspicious sign-in that has
    /// been held pending approval. The default composes a plain-text body and
    /// routes it through [`Mailer::send_text`], so every mailer inherits it.
    /// `country`/`ip` are optional (geoip may be off or the IP non-public).
    async fn send_login_approval_code(
        &self,
        to: &str,
        code: &str,
        country: Option<&str>,
        ip: Option<&str>,
        when: &str,
        user_agent: &str,
    ) -> AppResult<()> {
        let country = country.unwrap_or("unknown");
        let ip = ip.unwrap_or("unknown");
        let body = format!(
            "We are holding a sign-in to your account until you confirm it was you.\n\n\
             Country: {country}\n\
             IP address: {ip}\n\
             When: {when}\n\
             Device: {user_agent}\n\n\
             Enter this code to approve the sign-in:\n\n\
             {code}\n\n\
             The code expires in 15 minutes. If you did not just try to sign in, do not share this code, and change your password."
        );
        self.send_text(to, "Approve your sign-in", &body).await
    }
}

/// Dev mailer. Writes the link to `tracing` so smoke tests work without
/// SMTP. Never use in production.
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send_password_reset(&self, to: &str, reset_link: &str) -> AppResult<()> {
        tracing::info!(
            target: "mokosh_server.mailer",
            to = %to,
            link = %reset_link,
            "[DEV] would send password reset email",
        );
        Ok(())
    }

    async fn send_welcome(&self, to: &str, display_name: &str, setup_link: &str) -> AppResult<()> {
        tracing::info!(
            target: "mokosh_server.mailer",
            to = %to,
            name = %display_name,
            link = %setup_link,
            "[DEV] would send welcome email",
        );
        Ok(())
    }

    async fn send_text(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        tracing::info!(
            target: "mokosh_server.mailer",
            to = %to,
            subject = %subject,
            body_len = body.len(),
            "[DEV] would send text email",
        );
        Ok(())
    }
}

/// TLS mode for the SMTP connection.
#[derive(Clone, Debug)]
pub enum SmtpTls {
    /// Implicit TLS (port 465).
    Implicit,
    /// STARTTLS upgrade (port 587). Default.
    Starttls,
    /// Plain text. Local dev only (e.g. mailpit on port 1025).
    None,
}

impl SmtpTls {
    pub fn parse(raw: &str) -> AppResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "implicit" | "tls" | "smtps" => Ok(Self::Implicit),
            "starttls" | "" => Ok(Self::Starttls),
            "none" | "plain" | "off" => Ok(Self::None),
            other => Err(AppError::Configuration(format!(
                "SMTP_TLS={other:?} invalid; expected implicit | starttls | none"
            ))),
        }
    }

    /// Canonical lowercase name that round-trips through [`SmtpTls::parse`].
    /// Used when persisting the TLS mode into DB-backed email settings.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Implicit => "implicit",
            Self::Starttls => "starttls",
            Self::None => "none",
        }
    }
}

/// SMTP-backed mailer. Bytes leave the server.
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpMailer {
    /// Build from explicit pieces. Use [`SmtpMailer::from_env`] in main.
    pub fn new(
        host: &str,
        port: u16,
        tls: SmtpTls,
        username: Option<&str>,
        password: Option<&SecretString>,
        from: Mailbox,
    ) -> AppResult<Self> {
        let mut builder = match tls {
            SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|e| AppError::Configuration(format!("SMTP relay({host}): {e}")))?,
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| {
                    AppError::Configuration(format!("SMTP starttls_relay({host}): {e}"))
                })?,
            SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        }
        .port(port)
        .timeout(Some(Duration::from_secs(15)));

        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.credentials(Credentials::new(
                user.to_string(),
                pass.expose_secret().to_string(),
            ));
        }

        Ok(Self {
            transport: builder.build(),
            from,
        })
    }

    /// Start a `Message` for `to`, pre-populating the headers every outbound
    /// message must carry: `From`, `To`, and a unique `Message-ID`. `Date` is
    /// added automatically by lettre's `build`. Routing all sends through this
    /// helper guarantees no path can ship a message without a `Message-ID`.
    fn base_builder(&self, to: Mailbox) -> MessageBuilder {
        base_builder(&self.from, to)
    }
}

/// Generate a fresh, globally-unique `Message-ID` header value of the form
/// `<uuid@from-domain>`. lettre only emits a `Message-ID` when one is set
/// explicitly (its `hostname` feature is disabled here, so the `None` path
/// would fall back to `@localhost`); anchoring the id to the sending domain
/// keeps it RFC 5322 valid and deliverable. Google Workspace bounces messages
/// that carry no `Message-ID` at all (PMS-624).
fn new_message_id(from: &Mailbox) -> String {
    format!("<{}@{}>", Uuid::new_v4(), from.email.domain())
}

/// Build the shared header skeleton (`From`, `To`, `Message-ID`) for an
/// outbound message. Kept as a free function so it is unit-testable without
/// constructing an `SmtpMailer` (whose pooled transport needs a Tokio
/// runtime).
fn base_builder(from: &Mailbox, to: Mailbox) -> MessageBuilder {
    Message::builder()
        .from(from.clone())
        .to(to)
        .message_id(Some(new_message_id(from)))
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send_password_reset(&self, to: &str, reset_link: &str) -> AppResult<()> {
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| AppError::BadRequest(format!("invalid recipient {to}: {e}")))?;

        let text = format!(
            "We received a request to reset your Mokosh password.\n\n\
             Use the link below within 24 hours to set a new password.\n\n\
             {reset_link}\n\n\
             If you did not request this, ignore this message.\n",
        );
        let html = format!(
            r#"<!doctype html><html><body>
<p>We received a request to reset your Mokosh password.</p>
<p>Use the link below within 24 hours to set a new password.</p>
<p><a href="{reset_link}">{reset_link}</a></p>
<p>If you did not request this, ignore this message.</p>
</body></html>"#,
        );

        let msg = self
            .base_builder(to_mailbox)
            .subject("Reset your Mokosh password")
            .multipart(MultiPart::alternative_plain_html(text, html))?;

        self.transport.send(msg).await?;
        Ok(())
    }

    async fn send_welcome(&self, to: &str, display_name: &str, setup_link: &str) -> AppResult<()> {
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| AppError::BadRequest(format!("invalid recipient {to}: {e}")))?;

        let salutation = if display_name.trim().is_empty() {
            "Hello,".to_string()
        } else {
            format!("Hello {},", display_name.trim())
        };

        let text = format!(
            "{salutation}\n\n\
             An account has been created for you in Mokosh. Use the link\n\
             below to set your password and finish signing in.\n\n\
             {setup_link}\n",
        );
        let html = format!(
            r#"<!doctype html><html><body>
<p>{salutation}</p>
<p>An account has been created for you in Mokosh. Use the link below to set your password and finish signing in.</p>
<p><a href="{setup_link}">{setup_link}</a></p>
</body></html>"#,
        );

        let msg = self
            .base_builder(to_mailbox)
            .subject("Welcome to Mokosh")
            .multipart(MultiPart::alternative_plain_html(text, html))?;

        self.transport.send(msg).await?;
        Ok(())
    }

    async fn send_text(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| AppError::BadRequest(format!("invalid recipient {to}: {e}")))?;
        let msg = self
            .base_builder(to_mailbox)
            .subject(subject.to_string())
            .body(body.to_string())?;
        self.transport.send(msg).await?;
        Ok(())
    }
}

/// SMTP / mailer configuration sourced from env. `from_env` returns the
/// `LogMailer` when `SMTP_HOST` is unset or empty so dev environments
/// work without an SMTP server.
pub struct MailerConfig {
    pub host: Option<String>,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub from: String,
    pub tls: SmtpTls,
}

impl MailerConfig {
    pub fn from_env() -> AppResult<Self> {
        let host = std::env::var("SMTP_HOST").ok().filter(|s| !s.is_empty());
        let port = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(587);
        let username = std::env::var("SMTP_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let password = std::env::var("SMTP_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty())
            .map(SecretString::from);
        let from = std::env::var("SMTP_FROM")
            .unwrap_or_else(|_| "Mokosh <noreply@example.com>".to_string());
        let tls = SmtpTls::parse(&std::env::var("SMTP_TLS").unwrap_or_default())?;

        if username.is_some() && password.is_none() {
            return Err(AppError::Configuration(
                "SMTP_USERNAME is set but SMTP_PASSWORD is empty".to_string(),
            ));
        }

        Ok(Self {
            host,
            port,
            username,
            password,
            from,
            tls,
        })
    }

    /// Build the appropriate mailer for the current config. Selects
    /// `LogMailer` when SMTP_HOST is unset, `SmtpMailer` otherwise.
    pub fn build(self) -> AppResult<Arc<dyn Mailer>> {
        let Some(host) = self.host else {
            tracing::info!("SMTP_HOST unset; using LogMailer (emails will not be sent)");
            return Ok(Arc::new(LogMailer));
        };

        let from: Mailbox = self
            .from
            .parse()
            .map_err(|e| AppError::Configuration(format!("SMTP_FROM {:?}: {e}", self.from)))?;

        let mailer = SmtpMailer::new(
            &host,
            self.port,
            self.tls,
            self.username.as_deref(),
            self.password.as_ref(),
            from,
        )?;
        Ok(Arc::new(mailer))
    }
}

/// Live-swappable [`Mailer`] handle. Wraps the active mailer behind a
/// [`std::sync::RwLock`] so a settings change can rebuild and swap it in place
/// (PMS-638). Every consumer keeps holding an `Arc<dyn Mailer>` (this type,
/// upcast) and picks up the new configuration on its next send; `main` builds
/// one at startup and distributes clones, while the admin email-settings
/// handler holds the concrete `Arc<SharedMailer>` and calls [`SharedMailer::swap`].
/// The lock is only ever held long enough to clone the inner `Arc` out, never
/// across an `.await`.
pub struct SharedMailer {
    inner: std::sync::RwLock<Arc<dyn Mailer>>,
}

impl SharedMailer {
    pub fn new(inner: Arc<dyn Mailer>) -> Self {
        Self {
            inner: std::sync::RwLock::new(inner),
        }
    }

    /// Replace the active mailer. Takes effect on every consumer's next send.
    pub fn swap(&self, inner: Arc<dyn Mailer>) {
        *self.inner.write().expect("SharedMailer lock poisoned") = inner;
    }

    fn current(&self) -> Arc<dyn Mailer> {
        self.inner
            .read()
            .expect("SharedMailer lock poisoned")
            .clone()
    }
}

#[async_trait]
impl Mailer for SharedMailer {
    async fn send_password_reset(&self, to: &str, reset_link: &str) -> AppResult<()> {
        self.current().send_password_reset(to, reset_link).await
    }

    async fn send_welcome(&self, to: &str, display_name: &str, setup_link: &str) -> AppResult<()> {
        self.current()
            .send_welcome(to, display_name, setup_link)
            .await
    }

    async fn send_text(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        self.current().send_text(to, subject, body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from() -> Mailbox {
        "Mokosh <noreply@mokosh.example>".parse().unwrap()
    }

    #[test]
    fn new_message_id_is_unique_and_anchored_to_from_domain() {
        let from = test_from();
        let a = new_message_id(&from);
        let b = new_message_id(&from);

        assert_ne!(a, b, "each Message-ID must be unique");
        assert!(
            a.starts_with('<') && a.ends_with('>'),
            "must be angle-bracketed: {a}"
        );
        assert!(
            a.ends_with("@mokosh.example>"),
            "domain must match the From address: {a}"
        );
    }

    /// PMS-624: every outbound message must carry a `Message-ID` (Google
    /// Workspace bounces messages that lack one). Every send path funnels
    /// through `base_builder`, so asserting its output guards them all.
    #[test]
    fn base_builder_sets_message_id_and_date_headers() {
        let to: Mailbox = "user@recipient.example".parse().unwrap();

        let msg = base_builder(&test_from(), to)
            .subject("Header check")
            .body("body".to_string())
            .unwrap();

        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(
            raw.contains("Message-ID: <"),
            "missing Message-ID header:\n{raw}"
        );
        assert!(
            raw.contains("@mokosh.example>"),
            "Message-ID not anchored to the From domain:\n{raw}"
        );
        assert!(raw.contains("Date: "), "missing Date header:\n{raw}");
    }

    #[test]
    fn smtp_tls_round_trips_through_parse() {
        for mode in [SmtpTls::Implicit, SmtpTls::Starttls, SmtpTls::None] {
            let reparsed = SmtpTls::parse(mode.as_str()).unwrap();
            assert_eq!(reparsed.as_str(), mode.as_str());
        }
    }

    /// PMS-638: swapping the inner mailer must redirect subsequent sends to the
    /// new instance for every consumer holding the shared handle.
    #[tokio::test]
    async fn shared_mailer_swaps_the_active_mailer() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counting(Arc<AtomicUsize>);

        #[async_trait]
        impl Mailer for Counting {
            async fn send_password_reset(&self, _to: &str, _link: &str) -> AppResult<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn send_welcome(&self, _t: &str, _n: &str, _l: &str) -> AppResult<()> {
                Ok(())
            }
            async fn send_text(&self, _t: &str, _s: &str, _b: &str) -> AppResult<()> {
                Ok(())
            }
        }

        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let shared = SharedMailer::new(Arc::new(Counting(first.clone())));

        shared.send_password_reset("x@y.z", "link").await.unwrap();
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 0);

        shared.swap(Arc::new(Counting(second.clone())));
        shared.send_password_reset("x@y.z", "link").await.unwrap();
        assert_eq!(first.load(Ordering::SeqCst), 1, "old mailer no longer used");
        assert_eq!(
            second.load(Ordering::SeqCst),
            1,
            "new mailer receives the send"
        );
    }
}
