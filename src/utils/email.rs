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
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};

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
    fn parse(raw: &str) -> AppResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "implicit" | "tls" | "smtps" => Ok(Self::Implicit),
            "starttls" | "" => Ok(Self::Starttls),
            "none" | "plain" | "off" => Ok(Self::None),
            other => Err(AppError::Configuration(format!(
                "SMTP_TLS={other:?} invalid; expected implicit | starttls | none"
            ))),
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

        let msg = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
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

        let msg = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject("Welcome to Mokosh")
            .multipart(MultiPart::alternative_plain_html(text, html))?;

        self.transport.send(msg).await?;
        Ok(())
    }

    async fn send_text(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| AppError::BadRequest(format!("invalid recipient {to}: {e}")))?;
        let msg = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
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
