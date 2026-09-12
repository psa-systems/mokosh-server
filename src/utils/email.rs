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
use lettre::message::{
    header::ContentType, Attachment, Mailbox, MessageBuilder, MultiPart, SinglePart,
};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::config::{self, registry as keys};
use crate::utils::error::{AppError, AppResult};

/// PMS-761: who a client-facing message is from, as the client reads it.
///
/// Two plain strings rather than the `OrgIdentity` they are composed from, so
/// the mail layer keeps knowing nothing about tenants: this module owns
/// transport and body copy, `modules::tenants::identity` owns who the
/// organisation is and how its contact details are worded.
///
/// Both fields are required, because the defect this fixes was messages that
/// left them out. `contact_line` is never empty (`OrgIdentity::contact_line`
/// always names the organisation), so a body can append it unconditionally.
#[derive(Debug, Clone, Copy)]
pub struct SenderIdentity<'a> {
    /// The organisation's name, as shown to clients.
    pub org_name: &'a str,
    /// A complete sentence telling the client how to ask about this message.
    pub contact_line: &'a str,
}

/// What the quote sign-off email renders, beyond who it is from.
///
/// A struct rather than five positional `&str`s: four of them are strings in a
/// row, so a transposed pair would email the title as the total and nothing
/// would fail. Named fields make that impossible to write by accident, and
/// they keep the method under clippy's argument limit as the copy grows.
#[derive(Debug, Clone, Copy)]
pub struct QuoteReady<'a> {
    pub quote_number: &'a str,
    pub title: &'a str,
    pub total: &'a str,
    /// `None` when the quote carries no expiry, in which case the body omits
    /// the deadline line rather than printing a date the customer might act on.
    pub valid_until: Option<&'a str>,
    pub portal_link: &'a str,
}

/// What the invoice email renders, beyond who it is from. Same reasoning as
/// [`QuoteReady`].
///
/// PMS-991: the message is the invoice, not the payment link. `portal_link` is
/// `Some` only when the tenant has a connected payment gateway and the server
/// knows its portal origin; without it the body still says what is owed and by
/// when and carries the document. `pdf` is the stored document as issued
/// (PMS-959) when there is one.
#[derive(Debug, Clone, Copy)]
pub struct InvoiceSent<'a> {
    pub invoice_number: &'a str,
    pub amount_due: &'a str,
    pub due_date: &'a str,
    pub portal_link: Option<&'a str>,
    pub pdf: Option<&'a [u8]>,
}

/// PMS-1037: what a reminder about an overdue invoice says. The same fields
/// as [`InvoiceSent`] plus how far past due it is.
#[derive(Debug, Clone, Copy)]
pub struct InvoiceReminder<'a> {
    pub invoice_number: &'a str,
    pub amount_due: &'a str,
    pub due_date: &'a str,
    pub days_overdue: i64,
    pub portal_link: Option<&'a str>,
    pub pdf: Option<&'a [u8]>,
}

/// A file carried by a message (PMS-991).
#[derive(Debug, Clone, Copy)]
pub struct EmailAttachment<'a> {
    pub filename: &'a str,
    pub mime: &'a str,
    pub bytes: &'a [u8],
}

/// Anything that can send mokosh's transactional emails.
#[async_trait]
pub trait Mailer: Send + Sync {
    /// PMS-700: the single send primitive. `html` is the optional HTML
    /// alternative; `Some` produces a `multipart/alternative` message with
    /// `text` as the fallback part, `None` a single-part plain-text message.
    /// Body copy for transactional mail lives in `notification_templates`,
    /// so this trait carries no per-message templates.
    async fn send_multipart(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        html: Option<&str>,
    ) -> AppResult<()>;

    /// Plain-text convenience wrapper over [`Mailer::send_multipart`].
    async fn send_text(&self, to: &str, subject: &str, body: &str) -> AppResult<()> {
        self.send_multipart(to, subject, body, None).await
    }

    /// PMS-991: a plain-text message carrying files. The default sends the
    /// text alone and says so at `warn`, because a mailer that cannot carry
    /// an attachment must not silently pretend it did; the SMTP mailer
    /// overrides it with a `multipart/mixed` message.
    async fn send_with_attachments(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        attachments: &[EmailAttachment<'_>],
    ) -> AppResult<()> {
        if !attachments.is_empty() {
            tracing::warn!(
                target: "mokosh_server.mailer",
                to = %to,
                subject = %subject,
                attachments = attachments.len(),
                "this mailer cannot carry attachments; sending the text alone",
            );
        }
        self.send_multipart(to, subject, text, None).await
    }

    /// PMS-1013: exercise the mailer's transport without an unsolicited send.
    ///
    /// The default is `Ok(())`: a mailer that carries no bytes off the box
    /// (`LogMailer`) cannot fail to reach anything, so the verify is trivially
    /// true. `SmtpMailer` overrides this with a `NOOP` against the relay so an
    /// unreachable host, a wrong port or a rejected credential surfaces without
    /// asking somebody to send themselves a test message. Callers use it at
    /// boot (when the operator selected `smtp` and the deployment must fail
    /// loud, not on the first outbound), and behind the admin
    /// `POST /settings/email/verify` action.
    async fn verify(&self) -> AppResult<()> {
        Ok(())
    }

    /// PMS-673: tell a client contact that a quote is ready for their
    /// sign-off, linking them to the portal where they accept or decline.
    /// The default composes a plain-text body and routes it through
    /// [`Mailer::send_text`], so every mailer inherits it without a
    /// per-impl override.
    ///
    /// `valid_until` is optional because a quote need not carry an expiry;
    /// when absent the body simply omits the deadline line rather than
    /// printing a placeholder date the customer might act on.
    ///
    /// PMS-761: `from` is required. This message asks a client to commit money
    /// to a piece of work, and it used to do so without naming who was asking.
    async fn send_quote_ready(
        &self,
        to: &str,
        from: SenderIdentity<'_>,
        quote: QuoteReady<'_>,
    ) -> AppResult<()> {
        let SenderIdentity {
            org_name,
            contact_line,
        } = from;
        let QuoteReady {
            quote_number,
            title,
            total,
            valid_until,
            portal_link,
        } = quote;
        let deadline = match valid_until {
            Some(d) => format!("This quote is valid until {d}.\n\n"),
            None => String::new(),
        };
        let body = format!(
            "{org_name} has sent you a quote for your review and approval.\n\n\
             Quote: {quote_number}\n\
             For: {title}\n\
             Total: {total}\n\n\
             {deadline}\
             Review the full scope and accept or decline it here:\n\n\
             {portal_link}\n\n\
             {contact_line}"
        );
        self.send_text(
            to,
            &format!("Quote {quote_number} from {org_name} for your approval"),
            &body,
        )
        .await
    }

    /// PMS-711, reshaped by PMS-991: tell a client contact that an invoice has
    /// been sent, with the document attached and, when the tenant has a
    /// connected payment gateway, a link to the portal page whose "Pay Now"
    /// opens a provider checkout. Before PMS-991 the whole message was gated
    /// on the gateway, so a fresh install with none sent nothing on Send and
    /// nobody could tell; the invoice is the message and the link is an extra.
    /// The default composes a plain-text body and routes it through
    /// [`Mailer::send_with_attachments`], so every mailer inherits it.
    ///
    /// PMS-761: `from` is required, for the same reason as the quote. An email
    /// asking someone to pay, from nobody in particular, is indistinguishable
    /// from the invoice fraud it would be mistaken for.
    async fn send_invoice_sent(
        &self,
        to: &str,
        from: SenderIdentity<'_>,
        invoice: InvoiceSent<'_>,
    ) -> AppResult<()> {
        let SenderIdentity {
            org_name,
            contact_line,
        } = from;
        let InvoiceSent {
            invoice_number,
            amount_due,
            due_date,
            portal_link,
            pdf,
        } = invoice;
        let (subject, body) = compose_invoice_sent(
            org_name,
            contact_line,
            invoice_number,
            amount_due,
            due_date,
            portal_link,
            pdf.is_some(),
        );
        let filename = format!("{invoice_number}.pdf");
        let attachments: Vec<EmailAttachment<'_>> = pdf
            .map(|bytes| EmailAttachment {
                filename: &filename,
                mime: "application/pdf",
                bytes,
            })
            .into_iter()
            .collect();
        self.send_with_attachments(to, &subject, &body, &attachments)
            .await
    }

    /// PMS-1037: a reminder that an invoice is past due. Composed by
    /// [`compose_invoice_reminder`] and routed through
    /// [`Mailer::send_with_attachments`] like the invoice itself, so every
    /// mailer inherits it and a test mailer records it the same way.
    async fn send_invoice_reminder(
        &self,
        to: &str,
        from: SenderIdentity<'_>,
        reminder: InvoiceReminder<'_>,
    ) -> AppResult<()> {
        let SenderIdentity {
            org_name,
            contact_line,
        } = from;
        let (subject, body) = compose_invoice_reminder(org_name, contact_line, reminder);
        let filename = format!("{}.pdf", reminder.invoice_number);
        let attachments: Vec<EmailAttachment<'_>> = reminder
            .pdf
            .map(|bytes| EmailAttachment {
                filename: &filename,
                mime: "application/pdf",
                bytes,
            })
            .into_iter()
            .collect();
        self.send_with_attachments(to, &subject, &body, &attachments)
            .await
    }

    /// PMS-761: the two methods below take no [`SenderIdentity`], and should
    /// not be given one. They are mokosh speaking to its own user about their
    /// account, not an MSP speaking to a client. Dressing a "confirm this
    /// sign-in" message in a tenant's name and logo makes it look like the
    /// phishing it exists to prevent.
    ///
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
    async fn send_multipart(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        html: Option<&str>,
    ) -> AppResult<()> {
        tracing::info!(
            target: "mokosh_server.mailer",
            to = %to,
            subject = %subject,
            body_len = text.len(),
            html_len = html.map(str::len),
            "[DEV] would send email",
        );
        Ok(())
    }

    async fn send_with_attachments(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        attachments: &[EmailAttachment<'_>],
    ) -> AppResult<()> {
        tracing::info!(
            target: "mokosh_server.mailer",
            to = %to,
            subject = %subject,
            body_len = text.len(),
            attachments = attachments.len(),
            "[DEV] would send email with attachments",
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
}

/// PMS-774: the greeting every transactional message opens with.
///
/// The greeting WORD lives here and in the templates; only the name travels as
/// data. Both name columns this is fed from are `NOT NULL` but may hold empty
/// strings, so the blank case is real rather than theoretical, and a template
/// that appended a comma to a bare name opened on a stray comma.
///
/// Returns `Hello {name}` for a non-blank trimmed name and `Hello` otherwise;
/// the template supplies the punctuation that follows.
pub fn salutation(name: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        "Hello".to_string()
    } else {
        format!("Hello {name}")
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

/// Reject a recipient in the RFC 2606 reserved `.invalid` TLD, which is
/// guaranteed never to resolve. Mokosh mints `{sub}@unresolved.invalid`
/// placeholders for users whose IdP email is not verified yet (PMS-635); handing
/// one to the relay always bounces, so fail locally with an actionable error
/// instead of emitting a message that can only be rejected.
fn reject_undeliverable_recipient(to: &Mailbox) -> AppResult<()> {
    let domain = to.email.domain().to_ascii_lowercase();
    if domain == "invalid" || domain.ends_with(".invalid") {
        return Err(AppError::BadRequest(format!(
            "Refusing to send to the reserved non-routable address {}",
            to.email
        )));
    }
    Ok(())
}

/// The invoice email's subject and body (PMS-991). A free function so the
/// wording is pinned by a test without a mailer: the link paragraph appears
/// only when there is a link, and the attachment is named only when there is
/// one, so no recipient is told to click or open something that is not there.
pub fn compose_invoice_sent(
    org_name: &str,
    contact_line: &str,
    invoice_number: &str,
    amount_due: &str,
    due_date: &str,
    portal_link: Option<&str>,
    has_pdf: bool,
) -> (String, String) {
    let attached = if has_pdf {
        format!("The invoice is attached as {invoice_number}.pdf.\n\n")
    } else {
        String::new()
    };
    let pay = match portal_link {
        Some(link) => format!("Review the invoice and pay online here:\n\n{link}\n\n"),
        None => String::new(),
    };
    let body = format!(
        "{org_name} has sent you an invoice.\n\n\
         Invoice: {invoice_number}\n\
         Amount due: {amount_due}\n\
         Due: {due_date}\n\n\
         {attached}\
         {pay}\
         {contact_line}"
    );
    let subject = if portal_link.is_some() {
        format!("Invoice {invoice_number} from {org_name} is ready to pay")
    } else {
        format!("Invoice {invoice_number} from {org_name}")
    };
    (subject, body)
}

/// The reminder email's subject and body (PMS-1037). Names the amount, the
/// due date and how many days past it the invoice is; the pay link and the
/// attachment are mentioned only when present, as in [`compose_invoice_sent`].
pub fn compose_invoice_reminder(
    org_name: &str,
    contact_line: &str,
    reminder: InvoiceReminder<'_>,
) -> (String, String) {
    let InvoiceReminder {
        invoice_number,
        amount_due,
        due_date,
        days_overdue,
        portal_link,
        pdf,
    } = reminder;
    let days = if days_overdue == 1 {
        "1 day".to_string()
    } else {
        format!("{days_overdue} days")
    };
    let attached = if pdf.is_some() {
        format!("The invoice is attached as {invoice_number}.pdf.\n\n")
    } else {
        String::new()
    };
    let pay = match portal_link {
        Some(link) => format!("Review the invoice and pay online here:\n\n{link}\n\n"),
        None => String::new(),
    };
    let body = format!(
        "This is a reminder from {org_name} that an invoice is past due.\n\n\
         Invoice: {invoice_number}\n\
         Amount due: {amount_due}\n\
         Due: {due_date} ({days} ago)\n\n\
         {attached}\
         {pay}\
         If you have already paid, please disregard this message.\n\n\
         {contact_line}"
    );
    let subject = format!("Reminder: invoice {invoice_number} from {org_name} is {days} overdue");
    (subject, body)
}

/// Assemble a plain-text message carrying files (PMS-991): `multipart/mixed`
/// with the text first and each attachment after it. Free, like
/// [`build_message`], so a unit test can inspect the bytes.
fn build_message_with_attachments(
    from: &Mailbox,
    to: Mailbox,
    subject: &str,
    text: &str,
    attachments: &[EmailAttachment<'_>],
) -> AppResult<Message> {
    if attachments.is_empty() {
        return build_message(from, to, subject, text, None);
    }
    let mut mixed = MultiPart::mixed().singlepart(SinglePart::plain(text.to_string()));
    for attachment in attachments {
        let content_type = ContentType::parse(attachment.mime).map_err(|e| {
            AppError::Internal(format!(
                "attachment {} has an unusable content type {}: {e}",
                attachment.filename, attachment.mime
            ))
        })?;
        mixed = mixed.singlepart(
            Attachment::new(attachment.filename.to_string())
                .body(attachment.bytes.to_vec(), content_type),
        );
    }
    let msg = base_builder(from, to)
        .subject(subject.to_string())
        .multipart(mixed)?;
    Ok(msg)
}

/// Assemble the outbound message. `html` decides the shape: `Some` yields a
/// `multipart/alternative` carrying the plain text first and the HTML second,
/// `None` a single-part plain-text body. Free function so a unit test can
/// inspect the formatted bytes without an SMTP transport (PMS-700).
fn build_message(
    from: &Mailbox,
    to: Mailbox,
    subject: &str,
    text: &str,
    html: Option<&str>,
) -> AppResult<Message> {
    let builder = base_builder(from, to).subject(subject.to_string());
    let msg = match html {
        Some(html) => builder.multipart(MultiPart::alternative_plain_html(
            text.to_string(),
            html.to_string(),
        ))?,
        None => builder.body(text.to_string())?,
    };
    Ok(msg)
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send_multipart(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        html: Option<&str>,
    ) -> AppResult<()> {
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| AppError::BadRequest(format!("Invalid recipient {to}: {e}")))?;
        reject_undeliverable_recipient(&to_mailbox)?;
        let msg = build_message(&self.from, to_mailbox, subject, text, html)?;
        self.transport.send(msg).await?;
        Ok(())
    }

    async fn send_with_attachments(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        attachments: &[EmailAttachment<'_>],
    ) -> AppResult<()> {
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| AppError::BadRequest(format!("Invalid recipient {to}: {e}")))?;
        reject_undeliverable_recipient(&to_mailbox)?;
        let msg =
            build_message_with_attachments(&self.from, to_mailbox, subject, text, attachments)?;
        self.transport.send(msg).await?;
        Ok(())
    }

    /// PMS-1013: connect to the relay and send a NOOP. A refusal is an
    /// [`AppError::Configuration`] the caller reports the way `MailerConfig::build`
    /// does, so a boot-time verify fails loudly on the same class of error a
    /// live send would - just without asking somebody to receive a test message.
    async fn verify(&self) -> AppResult<()> {
        match self.transport.test_connection().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(AppError::Configuration(
                "SMTP relay refused the NOOP; the server is reachable but not accepting mail"
                    .to_string(),
            )),
            Err(e) => Err(AppError::Configuration(format!(
                "SMTP relay unreachable: {e}"
            ))),
        }
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
    /// PMS-982: the six `SMTP_*` values come from the configuration provider.
    /// Every emptiness and default rule below is unchanged; only where the
    /// string comes from moved.
    ///
    /// PMS-988 (deferred wiring): `SMTP_PASSWORD` will move onto the
    /// application-tier secret provider (`crate::app_secrets`) when that
    /// seam's migrate CLI lands (PMS-1012) and there is an operator runbook
    /// to walk. Until then the read stays on the configuration provider so
    /// a deployment whose `SMTP_PASSWORD` is a plain compose variable
    /// upgrades without a fatal boot.
    pub fn from_env() -> AppResult<Self> {
        let host = config::get(&keys::SMTP_HOST).filter(|s| !s.is_empty());
        let port = config::get(&keys::SMTP_PORT)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(587);
        let username = config::get(&keys::SMTP_USERNAME).filter(|s| !s.is_empty());
        let password = config::get(&keys::SMTP_PASSWORD)
            .filter(|s| !s.is_empty())
            .map(SecretString::from);
        let from = config::get(&keys::SMTP_FROM)
            .unwrap_or_else(|| "Mokosh <noreply@example.com>".to_string());
        let tls = SmtpTls::parse(&config::get(&keys::SMTP_TLS).unwrap_or_default())?;

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
    async fn send_multipart(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        html: Option<&str>,
    ) -> AppResult<()> {
        self.current().send_multipart(to, subject, text, html).await
    }

    async fn send_with_attachments(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        attachments: &[EmailAttachment<'_>],
    ) -> AppResult<()> {
        self.current()
            .send_with_attachments(to, subject, text, attachments)
            .await
    }

    async fn verify(&self) -> AppResult<()> {
        self.current().verify().await
    }
}

/// Which provider carries outbound mail for this deployment (PMS-1013).
///
/// The two are the strings the `deployment::provider` module already spells:
/// `log` for [`LogMailer`], `smtp` for [`SmtpMailer`]. A new provider is a
/// third variant here, its own [`EmailProviderKind::parse_name`] arm, and its
/// own construction branch in [`build_mailer`] - so the enum, the string
/// table and the construction site cannot drift out of step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailProviderKind {
    /// Writes the message to `tracing`; no bytes leave the box. The hosting
    /// profile's default in `self-hosted`, because no relay is available in a
    /// fresh customer image.
    Log,
    /// SMTP relay via [`SmtpMailer`]. The hosting profile's default in `saas`,
    /// because the deployed instance sets `SMTP_HOST` explicitly.
    Smtp,
}

impl EmailProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailProviderKind::Log => crate::utils::deployment::provider::LOG,
            EmailProviderKind::Smtp => crate::utils::deployment::provider::SMTP,
        }
    }

    /// A provider name to a kind. Blank is not a name here: [`EmailConfig::resolve`]
    /// settles an unset `MAIL_PROVIDER` against the profile default before it
    /// reaches this arm, so this cannot become a second place that knows the
    /// default and quietly falls back.
    pub fn parse_name(raw: &str) -> AppResult<Self> {
        use crate::utils::deployment::provider;
        match raw.trim() {
            s if s == provider::LOG => Ok(EmailProviderKind::Log),
            s if s == provider::SMTP => Ok(EmailProviderKind::Smtp),
            other => Err(AppError::Configuration(format!(
                "MAIL_PROVIDER {other:?} is not a known provider; expected 'log' or 'smtp'"
            ))),
        }
    }
}

/// The email provider selection for this process, and which of the two
/// mechanisms decided it: [`crate::utils::deployment::EnablementSource`].
///
/// PMS-1013 makes the choice deliberate. Log is never a silent fallback: it is
/// either the hosting profile's default (self-hosted with nothing set) or an
/// explicit `MAIL_PROVIDER=log` from the operator. An unusable `smtp` (no
/// `SMTP_HOST`) is a boot error rather than a silent degrade to Log.
#[derive(Clone, Copy, Debug)]
pub struct EmailConfig {
    pub provider: EmailProviderKind,
    pub source: crate::utils::deployment::EnablementSource,
}

impl EmailConfig {
    /// The ONE reader of `MAIL_PROVIDER`, matching the shape
    /// [`crate::secrets::SecretsConfig::from_env`] and
    /// [`crate::storage::StorageProviderKind::from_env`] follow. Reads through
    /// [`crate::config::get`], so the value goes through the same seam as
    /// every other declared key (PMS-982): the key is registered in
    /// `src/config/registry.rs` and cannot be read outside it.
    pub fn from_env(profile_default: &str) -> AppResult<Self> {
        let raw = crate::config::get(&crate::config::registry::MAIL_PROVIDER).unwrap_or_default();
        let smtp_host = crate::config::get(&crate::config::registry::SMTP_HOST)
            .filter(|s| !s.trim().is_empty());
        Self::resolve(profile_default, &raw, smtp_host.is_some())
    }

    /// The rule itself, split out so it can be tested without writing to
    /// process-global env under a concurrent test runner.
    ///
    /// Priority, from strongest to weakest:
    /// 1. An explicit `MAIL_PROVIDER=log|smtp` wins outright.
    /// 2. An unset `MAIL_PROVIDER` with `SMTP_HOST` set infers `smtp` as an
    ///    Explicit choice, so pre-PMS-1013 deployments that never named a
    ///    provider keep the SMTP mailer they had.
    /// 3. Otherwise the hosting profile's default stands.
    ///
    /// `profile_default` is the resolved provider NAME from `utils::deployment`
    /// (`log` in self-hosted, `smtp` in saas). This module never holds the
    /// deployment shape - PMS-904's `only_the_auth_service_and_the_startup_wiring_know_the_deployment_mode`
    /// guard covers that - it only needs a resolved name.
    pub fn resolve(profile_default: &str, raw: &str, smtp_host_set: bool) -> AppResult<Self> {
        let raw = raw.trim();
        if !raw.is_empty() {
            return Ok(Self {
                provider: EmailProviderKind::parse_name(raw)?,
                source: crate::utils::deployment::EnablementSource::Explicit,
            });
        }
        if smtp_host_set {
            return Ok(Self {
                provider: EmailProviderKind::Smtp,
                source: crate::utils::deployment::EnablementSource::Explicit,
            });
        }
        Ok(Self {
            provider: EmailProviderKind::parse_name(profile_default)?,
            source: crate::utils::deployment::EnablementSource::Profile,
        })
    }

    /// What this deployment explicitly configured, for the boot record and
    /// [`crate::providers::status`]. `None` when the profile's default stands.
    pub fn explicit_providers(&self) -> Option<Vec<&'static str>> {
        match self.source {
            crate::utils::deployment::EnablementSource::Explicit => {
                Some(vec![self.provider.as_str()])
            }
            crate::utils::deployment::EnablementSource::Profile => None,
        }
    }
}

/// Build a mailer for the selected provider, or refuse.
///
/// The ONE place an [`EmailProviderKind`] becomes an `Arc<dyn Mailer>`, so no
/// callsite can pick a provider of its own. Failure semantics match
/// [`crate::secrets::provider_from_env`] and
/// [`crate::storage::provider_from_env`]:
///
/// - `smtp` with no `SMTP_HOST` is refused, and a boot-time verify is expected
///   from the caller. The refusal message names the missing key so an operator
///   who typoed `MAIL_PROVIDER` learns which environment variable is empty.
/// - `log` with `SMTP_HOST` set is allowed but warns once, because a relay
///   configuration the operator entered and this seam will not use is more
///   often a mistake than a deliberate suppression.
/// - Building an [`SmtpMailer`] can still fail on a bad `SMTP_FROM` or a broken
///   TLS mode; the caller surfaces those the same way it does for the DB
///   override (`MailerConfig::build`).
///
/// Verifying that the relay actually answers is a separate step
/// ([`Mailer::verify`]), so the boot log is one call per capability: build
/// first, verify second.
pub fn build_mailer(
    kind: EmailProviderKind,
    mailer_config: MailerConfig,
) -> AppResult<Arc<dyn Mailer>> {
    match kind {
        EmailProviderKind::Log => {
            if mailer_config.host.is_some() {
                tracing::warn!(
                    "MAIL_PROVIDER=log but SMTP_HOST is set; the relay configuration is ignored. \
                     Set MAIL_PROVIDER=smtp to use it, or clear SMTP_HOST to remove the warning."
                );
            }
            Ok(Arc::new(LogMailer))
        }
        EmailProviderKind::Smtp => {
            if mailer_config.host.is_none() {
                return Err(AppError::Configuration(
                    "MAIL_PROVIDER=smtp requires SMTP_HOST; the selected provider has no relay to \
                     send through"
                        .to_string(),
                ));
            }
            mailer_config.build()
        }
    }
}

/// Process-wide record of the selected [`EmailProviderKind`], set by `main` at
/// boot after [`EmailConfig::from_env`] resolves. Every rebuild after that
/// point ([`crate::modules::settings::email::rebuild_and_swap`], the admin
/// verify action) reads this rather than re-resolving the provider from
/// process-global env under whatever the running settings request is holding,
/// so a runtime `MAIL_PROVIDER` swap is impossible: changing the selection
/// needs a restart, exactly like [`crate::config::registry::Tier::Bootstrap`]
/// keys do. Tests set it directly and callers read it through
/// [`selected_kind`].
static SELECTED_KIND: std::sync::OnceLock<EmailProviderKind> = std::sync::OnceLock::new();

/// Record the selection at boot. A second call from the same process is
/// silently ignored, matching [`crate::storage::init_from_env`]'s once-per-
/// process guarantee.
pub fn init_selected_kind(kind: EmailProviderKind) {
    let _ = SELECTED_KIND.set(kind);
}

/// The provider chosen at boot. `None` until [`init_selected_kind`] runs -
/// tests without a boot-wiring call reach this arm and treat it as SMTP-
/// compatible (the mailer built from `MailerConfig` decides), matching the
/// pre-PMS-1013 behaviour where nothing recorded a kind at all.
pub fn selected_kind() -> Option<EmailProviderKind> {
    SELECTED_KIND.get().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PMS-1037: the reminder names the amount, the due date and how far
    /// past it the invoice is, and mentions the link and the attachment only
    /// when they are there.
    #[test]
    fn the_reminder_says_how_overdue_and_only_what_is_there() {
        let (subject, body) = compose_invoice_reminder(
            "Acme MSP",
            "Reply to ap@acme.example",
            InvoiceReminder {
                invoice_number: "INV-000042",
                amount_due: "150.00 USD",
                due_date: "2026-08-01",
                days_overdue: 7,
                portal_link: None,
                pdf: Some(b"%PDF"),
            },
        );
        assert_eq!(
            subject,
            "Reminder: invoice INV-000042 from Acme MSP is 7 days overdue"
        );
        assert!(body.contains("Due: 2026-08-01 (7 days ago)"), "{body}");
        assert!(body.contains("attached as INV-000042.pdf"), "{body}");
        assert!(!body.contains("pay online"), "{body}");
        assert!(body.ends_with("Reply to ap@acme.example"), "{body}");

        let (subject, body) = compose_invoice_reminder(
            "Acme MSP",
            "",
            InvoiceReminder {
                invoice_number: "INV-1",
                amount_due: "1.00 USD",
                due_date: "2026-08-01",
                days_overdue: 1,
                portal_link: Some("https://portal.example/portal/invoices/x"),
                pdf: None,
            },
        );
        assert!(subject.ends_with("is 1 day overdue"), "{subject}");
        assert!(body.contains("https://portal.example/portal/invoices/x"));
        assert!(!body.contains("attached"), "{body}");
    }

    fn test_from() -> Mailbox {
        "Mokosh <noreply@mokosh.example>".parse().unwrap()
    }

    /// PMS-774: the templates append the punctuation, so the helper must never
    /// return a trailing space or comma of its own, and a blank name must not
    /// leave one behind either.
    #[test]
    fn salutation_covers_the_blank_and_named_cases() {
        assert_eq!(salutation("David"), "Hello David");
        assert_eq!(salutation("  David  "), "Hello David");
        assert_eq!(salutation(""), "Hello");
        assert_eq!(salutation("   "), "Hello");
        assert_eq!(salutation("\t\n"), "Hello");

        // The comma the templates add lands directly after the greeting in
        // both cases, which is the whole point of returning it unpunctuated.
        assert_eq!(format!("{},", salutation("")), "Hello,");
        assert_eq!(format!("{},", salutation("David")), "Hello David,");
    }

    /// PMS-774: the greeting word belongs to the template, never to the data.
    ///
    /// `forms.request_link` used to pass the WORD "Hello" as the recipient's
    /// NAME when there was no contact, so the same placeholder rendered a
    /// greeting for one recipient and a bare name for another. Fail if any
    /// dispatch site puts a greeting back into its context; the templates all
    /// take `{{salutation}}` now, so a name that is also a greeting renders
    /// twice.
    #[test]
    fn no_dispatch_context_supplies_a_greeting_word() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dispatchers = [
            "src/modules/forms/request_links.rs",
            "src/modules/auth/service.rs",
            "src/modules/contacts/service.rs",
        ];
        // Split so the needles never match this guard's own source file.
        let needles = [
            concat!("\"Hel", "lo"),
            concat!("\"H", "i "),
            concat!("\"De", "ar "),
        ];

        let mut hits: Vec<String> = Vec::new();
        for file in dispatchers {
            let path = root.join(file);
            let text = std::fs::read_to_string(&path).expect("read dispatch source");
            for needle in needles {
                if text.contains(needle) {
                    hits.push(format!("{file}: {needle}"));
                }
            }
        }

        assert!(
            hits.is_empty(),
            "a greeting word is back in a dispatch context; the template owns the \
             greeting and `salutation` composes it: {hits:?}",
        );
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

    /// PMS-635: a user whose IdP email is unverified is mirrored under
    /// `{sub}@unresolved.invalid`. That domain can only bounce, so the send is
    /// refused locally rather than handed to the relay.
    #[test]
    fn reserved_invalid_recipients_are_refused() {
        for addr in [
            "7fa2b249-6132-4abc-90de-1234567890ab@unresolved.invalid",
            "someone@UNRESOLVED.INVALID",
            "someone@invalid",
        ] {
            let to: Mailbox = addr.parse().unwrap();
            assert!(
                reject_undeliverable_recipient(&to).is_err(),
                "must refuse the reserved address {addr}"
            );
        }
    }

    #[test]
    fn routable_recipients_are_accepted() {
        for addr in ["user@recipient.example", "user@invalidation.example.com"] {
            let to: Mailbox = addr.parse().unwrap();
            assert!(
                reject_undeliverable_recipient(&to).is_ok(),
                "must accept the routable address {addr}"
            );
        }
    }

    #[test]
    fn smtp_tls_round_trips_through_parse() {
        for mode in [SmtpTls::Implicit, SmtpTls::Starttls, SmtpTls::None] {
            let reparsed = SmtpTls::parse(mode.as_str()).unwrap();
            assert_eq!(reparsed.as_str(), mode.as_str());
        }
    }

    /// PMS-700: an authored `body_html` must reach the wire as the second part
    /// of a `multipart/alternative` message, with the plain text kept as the
    /// fallback part.
    #[test]
    fn build_message_emits_the_html_part_as_a_multipart_alternative() {
        let to: Mailbox = "user@recipient.example".parse().unwrap();

        let msg = build_message(
            &test_from(),
            to,
            "Rendered subject",
            "plain fallback body",
            Some("<html><body><p>rendered html body</p></body></html>"),
        )
        .unwrap();

        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(
            raw.contains("multipart/alternative"),
            "message is not multipart/alternative:\n{raw}"
        );
        assert!(
            raw.contains("text/html"),
            "message carries no HTML part:\n{raw}"
        );
        assert!(
            raw.contains("rendered html body"),
            "HTML part content missing:\n{raw}"
        );
        assert!(
            raw.contains("plain fallback body"),
            "plain-text fallback part missing:\n{raw}"
        );
    }

    /// PMS-700: a template with no `body_html` must still produce the previous
    /// single-part plain-text message, not an empty HTML alternative.
    #[test]
    fn build_message_without_html_stays_single_part_plain_text() {
        let to: Mailbox = "user@recipient.example".parse().unwrap();

        let msg = build_message(&test_from(), to, "Subject", "plain only body", None).unwrap();

        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(
            !raw.contains("multipart/"),
            "message should not be multipart:\n{raw}"
        );
        assert!(
            !raw.contains("text/html"),
            "message should carry no HTML part:\n{raw}"
        );
        assert!(
            raw.contains("plain only body"),
            "plain-text body missing:\n{raw}"
        );
    }

    /// PMS-638: swapping the inner mailer must redirect subsequent sends to the
    /// new instance for every consumer holding the shared handle.
    #[tokio::test]
    async fn shared_mailer_swaps_the_active_mailer() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counting(Arc<AtomicUsize>);

        #[async_trait]
        impl Mailer for Counting {
            async fn send_multipart(
                &self,
                _to: &str,
                _subject: &str,
                _text: &str,
                _html: Option<&str>,
            ) -> AppResult<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let shared = SharedMailer::new(Arc::new(Counting(first.clone())));

        shared.send_text("x@y.z", "subject", "body").await.unwrap();
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 0);

        shared.swap(Arc::new(Counting(second.clone())));
        shared.send_text("x@y.z", "subject", "body").await.unwrap();
        assert_eq!(first.load(Ordering::SeqCst), 1, "old mailer no longer used");
        assert_eq!(
            second.load(Ordering::SeqCst),
            1,
            "new mailer receives the send"
        );
    }

    /// Captures the last message so the trait's default bodies can be asserted
    /// without SMTP, a database or a router.
    #[derive(Default)]
    struct Capturing(std::sync::Mutex<Option<(String, String, String)>>);

    #[async_trait]
    impl Mailer for Capturing {
        async fn send_multipart(
            &self,
            to: &str,
            subject: &str,
            text: &str,
            _html: Option<&str>,
        ) -> AppResult<()> {
            *self.0.lock().unwrap() = Some((to.to_string(), subject.to_string(), text.to_string()));
            Ok(())
        }
    }

    impl Capturing {
        fn taken(&self) -> (String, String, String) {
            self.0.lock().unwrap().clone().expect("a message was sent")
        }
    }

    fn contoso() -> SenderIdentity<'static> {
        SenderIdentity {
            org_name: "Contoso IT",
            contact_line:
                "Questions about this? Contact the service desk at Contoso IT on 555-0100.",
        }
    }

    /// PMS-761: a client asked to approve spend is told who is asking, in the
    /// subject as well as the body. The subject matters on its own: it is what
    /// the recipient decides to open on, and "Quote Q-1001 for your approval"
    /// from an unknown sender reads like the fraud it is not.
    #[tokio::test]
    async fn the_quote_email_names_the_organisation_and_how_to_reach_it() {
        let mailer = Capturing::default();
        mailer
            .send_quote_ready(
                "client@recipient.example",
                contoso(),
                QuoteReady {
                    quote_number: "Q-1001",
                    title: "Network refresh",
                    total: "4500.00 USD",
                    valid_until: Some("2026-09-01"),
                    portal_link: "http://portal.example/portal/quotes/1",
                },
            )
            .await
            .unwrap();

        let (to, subject, body) = mailer.taken();
        assert_eq!(to, "client@recipient.example");
        assert_eq!(subject, "Quote Q-1001 from Contoso IT for your approval");
        assert!(
            body.starts_with("Contoso IT has sent you a quote"),
            "the body opens by naming the sender:\n{body}"
        );
        assert!(
            body.ends_with(contoso().contact_line),
            "the contact line closes the message:\n{body}"
        );
        assert!(body.contains("valid until 2026-09-01"), "{body}");
    }

    /// The deadline line is the one optional piece; without an expiry it must
    /// vanish rather than print a date the customer might act on.
    #[tokio::test]
    async fn a_quote_without_an_expiry_omits_the_deadline() {
        let mailer = Capturing::default();
        mailer
            .send_quote_ready(
                "client@recipient.example",
                contoso(),
                QuoteReady {
                    quote_number: "Q-1002",
                    title: "Ad-hoc work",
                    total: "100.00 USD",
                    valid_until: None,
                    portal_link: "http://portal.example/portal/quotes/2",
                },
            )
            .await
            .unwrap();

        let (_, _, body) = mailer.taken();
        assert!(!body.contains("valid until"), "{body}");
        assert!(body.contains("Contoso IT"), "{body}");
    }

    /// PMS-761: same for the invoice. An unattributed request for payment is
    /// the exact shape of invoice fraud, so the organisation is named in the
    /// subject and the opening sentence both.
    #[tokio::test]
    async fn the_invoice_email_names_the_organisation_and_how_to_reach_it() {
        let mailer = Capturing::default();
        mailer
            .send_invoice_sent(
                "client@recipient.example",
                contoso(),
                InvoiceSent {
                    invoice_number: "INV-2050",
                    amount_due: "1200.00 USD",
                    due_date: "2026-09-30",
                    portal_link: Some("http://portal.example/portal/invoices/1"),
                    pdf: None,
                },
            )
            .await
            .unwrap();

        let (_, subject, body) = mailer.taken();
        assert_eq!(subject, "Invoice INV-2050 from Contoso IT is ready to pay");
        assert!(
            body.starts_with("Contoso IT has sent you an invoice"),
            "the body opens by naming the sender:\n{body}"
        );
        assert!(body.ends_with(contoso().contact_line), "{body}");
    }

    /// PMS-991: the invoice is the message and the link is an extra. Without a
    /// gateway there is no link and no "pay online" sentence to point at
    /// nothing; without a document there is no "attached" sentence either.
    #[test]
    fn the_invoice_email_only_promises_what_it_carries() {
        let (subject, body) = compose_invoice_sent(
            "Contoso IT",
            "Questions? Call us.",
            "INV-1",
            "50.00 USD",
            "2026-09-30",
            None,
            false,
        );
        assert_eq!(subject, "Invoice INV-1 from Contoso IT");
        assert!(!body.contains("pay online"), "{body}");
        assert!(!body.contains("attached"), "{body}");
        assert!(body.contains("Amount due: 50.00 USD"), "{body}");
        assert!(body.ends_with("Questions? Call us."), "{body}");

        let (subject, body) = compose_invoice_sent(
            "Contoso IT",
            "Questions? Call us.",
            "INV-1",
            "50.00 USD",
            "2026-09-30",
            Some("http://portal.example/portal/invoices/1"),
            true,
        );
        assert_eq!(subject, "Invoice INV-1 from Contoso IT is ready to pay");
        assert!(body.contains("attached as INV-1.pdf"), "{body}");
        assert!(
            body.contains("pay online here:\n\nhttp://portal.example/portal/invoices/1"),
            "{body}"
        );
    }

    /// PMS-991: the SMTP shape. A message with a file is `multipart/mixed`
    /// with the text first and the file as a named, typed attachment; one
    /// without a file is the plain message it always was.
    #[test]
    fn a_message_with_a_file_is_multipart_mixed() {
        let to: Mailbox = "client@recipient.example".parse().unwrap();
        let bytes = b"%PDF-1.3 not really".to_vec();
        let msg = build_message_with_attachments(
            &test_from(),
            to.clone(),
            "Invoice INV-1",
            "Hello",
            &[EmailAttachment {
                filename: "INV-1.pdf",
                mime: "application/pdf",
                bytes: &bytes,
            }],
        )
        .unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("multipart/mixed"), "{raw}");
        assert!(raw.contains("application/pdf"), "{raw}");
        assert!(raw.contains("INV-1.pdf"), "{raw}");
        assert!(raw.contains("Hello"), "{raw}");

        let plain = build_message_with_attachments(&test_from(), to, "Invoice INV-1", "Hello", &[])
            .unwrap();
        let raw = String::from_utf8(plain.formatted()).unwrap();
        assert!(!raw.contains("multipart"), "{raw}");
    }

    /// PMS-761: the account-security emails are mokosh speaking to its own
    /// user, not an MSP speaking to a client, and must stay unbranded. A tenant
    /// name and logo on "approve your sign-in" is what phishing looks like.
    #[tokio::test]
    async fn the_security_emails_carry_no_organisation_identity() {
        let mailer = Capturing::default();
        mailer
            .send_login_approval_code(
                "user@msp.example",
                "123456",
                Some("NZ"),
                Some("203.0.113.7"),
                "2026-08-11 10:00 UTC",
                "Firefox on Linux",
            )
            .await
            .unwrap();
        let (_, subject, body) = mailer.taken();
        assert_eq!(subject, "Approve your sign-in");
        assert!(!body.contains("Contoso"), "{body}");

        mailer
            .send_new_login_location(
                "user@msp.example",
                "NZ",
                "203.0.113.7",
                "2026-08-11 10:00 UTC",
                "Firefox on Linux",
                "http://spa.example/settings/security",
            )
            .await
            .unwrap();
        let (_, subject, body) = mailer.taken();
        assert_eq!(subject, "New sign-in to your account");
        assert!(!body.contains("Contoso"), "{body}");
    }

    /// PMS-1013: a provider name to a kind, and the two enum names match the
    /// strings the `deployment::provider` table already spells. The parse
    /// refuses anything else - a typo does not silently become one of the two.
    #[test]
    fn email_provider_kind_parses_the_known_names_only() {
        assert_eq!(
            EmailProviderKind::parse_name("log").unwrap(),
            EmailProviderKind::Log
        );
        assert_eq!(
            EmailProviderKind::parse_name(" smtp ").unwrap(),
            EmailProviderKind::Smtp
        );
        assert_eq!(
            EmailProviderKind::Log.as_str(),
            crate::utils::deployment::provider::LOG
        );
        assert_eq!(
            EmailProviderKind::Smtp.as_str(),
            crate::utils::deployment::provider::SMTP
        );
        for hostile in ["", "LOG", "SMTP", "logmailer", "smtps", "sendgrid"] {
            assert!(
                EmailProviderKind::parse_name(hostile).is_err(),
                "{hostile:?} must be refused"
            );
        }
    }

    /// PMS-1013: unset MAIL_PROVIDER with SMTP_HOST set infers smtp
    /// (backward compat with the pre-PMS-1013 implicit rule) and marks the
    /// source Explicit; unset with no host takes the profile default and
    /// marks it Profile; an explicit value wins over both regardless of the
    /// host, and an unrecognised value is refused.
    #[test]
    fn email_config_resolve_covers_the_priority_ladder() {
        use crate::utils::deployment::provider;

        // Explicit MAIL_PROVIDER wins.
        let explicit_log = EmailConfig::resolve(provider::SMTP, "log", true).unwrap();
        assert_eq!(explicit_log.provider, EmailProviderKind::Log);
        assert_eq!(
            explicit_log.source,
            crate::utils::deployment::EnablementSource::Explicit
        );
        let explicit_smtp = EmailConfig::resolve(provider::LOG, "smtp", false);
        // MAIL_PROVIDER=smtp is valid even with no SMTP_HOST at the parse
        // step; the boot-time check in `build_mailer` is what refuses.
        assert!(explicit_smtp.is_ok());

        // Unset MAIL_PROVIDER + SMTP_HOST present infers smtp Explicit.
        let inferred = EmailConfig::resolve(provider::LOG, "", true).unwrap();
        assert_eq!(inferred.provider, EmailProviderKind::Smtp);
        assert_eq!(
            inferred.source,
            crate::utils::deployment::EnablementSource::Explicit,
            "SMTP_HOST is the pre-PMS-1013 explicit signal; keeping that shape means \
             existing deployments do not silently switch to LogMailer"
        );

        // Unset MAIL_PROVIDER + no host takes the profile default (Profile).
        let profile_log = EmailConfig::resolve(provider::LOG, "", false).unwrap();
        assert_eq!(profile_log.provider, EmailProviderKind::Log);
        assert_eq!(
            profile_log.source,
            crate::utils::deployment::EnablementSource::Profile
        );
        let profile_smtp = EmailConfig::resolve(provider::SMTP, "", false).unwrap();
        assert_eq!(profile_smtp.provider, EmailProviderKind::Smtp);
        assert_eq!(
            profile_smtp.source,
            crate::utils::deployment::EnablementSource::Profile
        );

        // A typo refuses to resolve rather than falling through to a default.
        assert!(EmailConfig::resolve(provider::LOG, "smpt", true).is_err());
        assert!(EmailConfig::resolve(provider::LOG, "quiet", false).is_err());
    }

    /// PMS-1013: `explicit_providers` reports only what the operator chose
    /// (or the inferred smtp signal), so the boot record can distinguish a
    /// provider left on by the profile from one the operator selected. This
    /// is what the status collector's `ProviderOverrides` reads.
    #[test]
    fn email_config_explicit_providers_matches_the_source() {
        use crate::utils::deployment::provider;

        assert_eq!(
            EmailConfig::resolve(provider::LOG, "smtp", false)
                .unwrap()
                .explicit_providers()
                .unwrap(),
            vec![provider::SMTP]
        );
        assert!(EmailConfig::resolve(provider::LOG, "", false)
            .unwrap()
            .explicit_providers()
            .is_none());
    }

    /// PMS-1013: `build_mailer` is fail-loud on `smtp` with no host, and it
    /// warns rather than refusing on `log` with a host so a mistaken relay
    /// configuration surfaces without stopping a deployment that deliberately
    /// suppressed outbound mail.
    #[test]
    fn build_mailer_refuses_smtp_without_a_host_and_allows_log_regardless() {
        let cfg = MailerConfig {
            host: None,
            port: 587,
            username: None,
            password: None,
            from: "Mokosh <noreply@example.com>".to_string(),
            tls: SmtpTls::Starttls,
        };
        match build_mailer(EmailProviderKind::Smtp, cfg) {
            Err(AppError::Configuration(msg)) => {
                assert!(msg.contains("SMTP_HOST"), "{msg}");
                assert!(msg.contains("MAIL_PROVIDER=smtp"), "{msg}");
            }
            Err(other) => panic!("expected Configuration error, got {other}"),
            Ok(_) => panic!("smtp without host must refuse"),
        }

        let log_cfg = MailerConfig {
            host: Some("smtp.example".to_string()),
            port: 587,
            username: None,
            password: None,
            from: "Mokosh <noreply@example.com>".to_string(),
            tls: SmtpTls::Starttls,
        };
        assert!(
            build_mailer(EmailProviderKind::Log, log_cfg).is_ok(),
            "MAIL_PROVIDER=log must build LogMailer regardless of SMTP_HOST; the warning \
             is the operator signal"
        );
    }

    /// PMS-1013: LogMailer's default verify is trivially Ok. SmtpMailer's
    /// verify is tested against a live relay in integration; the unit test
    /// pins that a mailer with no transport reports success without a network
    /// call, so the boot verify is safe on `log` deployments.
    #[tokio::test]
    async fn log_mailer_verify_is_ok() {
        let mailer: Arc<dyn Mailer> = Arc::new(LogMailer);
        mailer.verify().await.expect("LogMailer verify is trivial");
    }
}
