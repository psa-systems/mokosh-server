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

    /// Compose + submit one `multipart/alternative` message
    /// (text/plain first, text/html second). Every client we care
    /// about prefers the HTML part; text/plain helps deliverability
    /// scoring and is what plain-text clients (or terminal-based
    /// readers) see.
    async fn send_multipart(
        &self,
        to: Mailbox,
        subject: &str,
        text: String,
        html: String,
    ) -> Result<(), AuthError> {
        use lettre::message::MultiPart;
        let msg = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .multipart(MultiPart::alternative_plain_html(text, html))
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
        let (subject, text, html) = templates::invite_email(invite, inviter, &link);
        self.send_multipart(to, &subject, text, html).await
    }

    async fn send_signup(&self, email: &str, raw_token: &str) -> Result<(), AuthError> {
        let link = self.build_link("signup", raw_token);
        let to = parse_recipient(email)?;
        let (subject, text, html) = templates::signup_email(email, &link);
        self.send_multipart(to, &subject, text, html).await
    }
}

// --- Templates ----------------------------------------------------------
//
// Hand-written text and HTML bodies. No template engine: the variable
// set is tiny (recipient, inviter, tenant name, link, role) and
// every byte is grep-able. Every HTML interpolation goes through
// `html_escape`; plain-text bodies do not escape. Inline CSS only,
// no <link rel="stylesheet">, no web fonts, no external images.
// See docs/mokosh-smtp/04-templates.md.

pub mod templates {
    use mokosh_auth_core::{Invite, User, UserRole};

    use super::{display_name, html_escape};

    /// User-facing version of the role enum. The auth-core enum's
    /// `as_str()` is for storage; this is for humans.
    fn role_label(role: UserRole) -> &'static str {
        match role {
            UserRole::Admin => "Admin",
            UserRole::Manager => "Manager",
            UserRole::Finance => "Finance",
            UserRole::Member => "Member",
            UserRole::ReadOnly => "Read only",
        }
    }

    /// Invite email. Returns `(subject, text, html)`.
    pub fn invite_email(invite: &Invite, inviter: &User, link: &str)
        -> (String, String, String)
    {
        let inviter_name = display_name(inviter);
        let role = role_label(invite.role);
        // We don't have the tenant name in scope here (the auth crate
        // doesn't own public.tenants). The handler logs the link
        // + tenant name separately; the email body uses a generic
        // "Mokosh" until phase 4-bis threads the tenant-name closure
        // through the mailer. Acceptable for now.
        let subject = "You're invited to Mokosh".to_string();

        let text = format!(
            "Hi,\n\
\n\
{inviter_name} ({inviter_email}) invited you to join Mokosh as {role}.\n\
\n\
Accept the invite by clicking this link in the next 7 days:\n\
\n\
  {link}\n\
\n\
If you did not expect this invite, you can safely ignore this email.\n\
\n\
(This is an automated message; do not reply.)\n",
            inviter_name = inviter_name,
            inviter_email = inviter.email,
            role = role,
            link = link,
        );

        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:14px;color:#1f2937;max-width:560px;margin:24px auto;padding:0 16px;">
  <p>Hi,</p>
  <p><strong>{inviter_name}</strong> (<a href="mailto:{inviter_email}" style="color:#2563eb;">{inviter_email}</a>) invited you to join Mokosh as <em>{role}</em>.</p>
  <p>Accept the invite within 7 days:</p>
  <p><a href="{link}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:600;">Accept invite</a></p>
  <p style="font-size:12px;color:#6b7280;">If the button does not work, paste this URL into your browser:<br><span style="font-family:ui-monospace,Menlo,monospace;word-break:break-all;">{link}</span></p>
  <p style="font-size:12px;color:#6b7280;">If you did not expect this invite, you can safely ignore this email.</p>
  <p style="font-size:11px;color:#9ca3af;">This is an automated message; do not reply.</p>
</body>
</html>
"#,
            inviter_name = html_escape(&inviter_name),
            inviter_email = html_escape(&inviter.email),
            role = html_escape(role),
            link = html_escape(link),
        );

        (subject, text, html)
    }

    /// Signup confirmation email. Same body shape whether the email
    /// is in use or not (enumeration-resistance is enforced at the
    /// handler level; the body must not give it away).
    pub fn signup_email(email: &str, link: &str) -> (String, String, String) {
        let subject = "Confirm your Mokosh account".to_string();

        let text = format!(
            "Hi,\n\
\n\
A Mokosh account creation was requested for {email}. Click the link\n\
below to set a password and finish creating the account. The link is\n\
valid for 24 hours and can only be used once.\n\
\n\
  {link}\n\
\n\
If you did not request this, you can safely ignore this email; nothing\n\
will happen and no account will be created.\n\
\n\
(This is an automated message; do not reply.)\n",
            email = email,
            link = link,
        );

        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;font-size:14px;color:#1f2937;max-width:560px;margin:24px auto;padding:0 16px;">
  <p>Hi,</p>
  <p>A Mokosh account creation was requested for <strong>{email}</strong>. Click below to set a password and finish.</p>
  <p><a href="{link}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:600;">Finish creating account</a></p>
  <p style="font-size:12px;color:#6b7280;">The link is valid for 24 hours and can only be used once.</p>
  <p style="font-size:12px;color:#6b7280;">If the button does not work, paste this URL into your browser:<br><span style="font-family:ui-monospace,Menlo,monospace;word-break:break-all;">{link}</span></p>
  <p style="font-size:12px;color:#6b7280;">If you did not request this, you can safely ignore this email.</p>
  <p style="font-size:11px;color:#9ca3af;">This is an automated message; do not reply.</p>
</body>
</html>
"#,
            email = html_escape(email),
            link = html_escape(link),
        );

        (subject, text, html)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use mokosh_auth_core::{TenantId, UserId, UserRole, UserStatus};

    fn stub_user(email: &str, first: Option<&str>, last: Option<&str>) -> User {
        User {
            id: UserId(uuid::Uuid::nil()),
            tenant_id: TenantId(uuid::Uuid::nil()),
            email: email.to_string(),
            email_verified_at: Some(Utc::now()),
            password_hash: None,
            role: UserRole::Admin,
            status: UserStatus::Active,
            first_name: first.map(String::from),
            last_name: last.map(String::from),
            timezone: "UTC".into(),
            locale: "en-US".into(),
            mfa_enrolled: false,
            last_login_at: None,
            last_active_tenant: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn stub_invite(email: &str) -> Invite {
        Invite {
            id: uuid::Uuid::nil(),
            tenant_id: TenantId(uuid::Uuid::nil()),
            email: email.to_string(),
            role: UserRole::Member,
            invited_by: UserId(uuid::Uuid::nil()),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(7),
            used_at: None,
            used_by: None,
            revoked_at: None,
            revoked_by: None,
            revoke_reason: None,
            note: None,
        }
    }

    #[test]
    fn invite_html_escapes_inviter_name() {
        let inviter = stub_user("inv@x.test", Some("<b>Bob</b>"), None);
        let invite = stub_invite("you@x.test");
        let (_, _, html) = templates::invite_email(&invite, &inviter, "https://x/y");
        assert!(html.contains("&lt;b&gt;Bob&lt;/b&gt;"));
        assert!(!html.contains("<b>Bob</b>"));
    }

    #[test]
    fn invite_text_does_not_escape() {
        let inviter = stub_user("inv@x.test", Some("Bob & Bob"), None);
        let invite = stub_invite("you@x.test");
        let (_, text, _) = templates::invite_email(&invite, &inviter, "https://x/y");
        assert!(text.contains("Bob & Bob"));
        assert!(!text.contains("&amp;"));
    }

    #[test]
    fn signup_link_round_trips() {
        let link = "https://x/y/abc-DEF_-123";
        let (_, text, html) = templates::signup_email("a@b.test", link);
        assert!(text.contains(link));
        assert!(html.contains(link)); // URL-safe chars are also HTML-safe.
    }

    #[test]
    fn signup_html_escapes_email_local_part() {
        let (_, _, html) = templates::signup_email("<script>@b.test", "https://x");
        assert!(html.contains("&lt;script&gt;@b.test"));
        assert!(!html.contains("<script>@b.test"));
    }
}
