# Mail transport: self-hosted vs SaaS

Three `Mailer` implementations exist in `src/utils/email.rs`: `LogMailer`,
`SmtpMailer` and `ApiMailer` (PMS-1482). Which one a process builds is decided
once, at boot, by `EmailProviderKind` through the single construction path in
`build_mailer`; nothing downstream (composition, the `Mailer` trait's own
callers) knows or cares which one it got.

## The three providers

| provider (`MAIL_PROVIDER` value) | kind | transport |
|---|---|---|
| `log` | `LogMailer` | writes the message to the log, sends nothing |
| `smtp` | `SmtpMailer` | direct SMTP to `SMTP_HOST`, this process's own connection |
| `bunyip` | `ApiMailer` | HTTPS `POST /v1/mailer/send` to Bunyip's shared mailer relay (BUNYIP-602) |

`log` and `smtp` are the two hosting-profile defaults (see
[Default providers](self-hosted-vs-saas.md#default-providers-pms-1011)):
`self-hosted` defaults to `log`, `saas` defaults to `smtp`. `bunyip` is not
either profile's default; it is only ever selected by an operator setting
`MAIL_PROVIDER=bunyip` explicitly. PMS-1018 confirmed the deployed `saas`
instance already sends through plain SMTP directly (`mail.psa.systems`), so
this doc does not change that: `bunyip` exists as a selectable name in
`ProviderKind::known_providers()` without being anybody's row in
`SAAS_PROVIDER_DEFAULTS`.

## Data flow by mode

**`self-hosted`, unset `MAIL_PROVIDER`, no `SMTP_HOST`:** `LogMailer`. No
network call leaves the process; the composed subject and body are written to
the log at `info`. This is what lets a fresh self-hosted clone boot and run
without any mail infrastructure.

**Either mode, `SMTP_HOST` set (and `MAIL_PROVIDER` unset or `smtp`):**
`SmtpMailer`. The process holds its own SMTP connection, authenticating with
`SMTP_USERNAME`/`SMTP_PASSWORD` when set, and sends the composed message
directly to that server. This is the deployed `saas` shape today (PMS-1018).

**Either mode, `MAIL_PROVIDER=bunyip`:** `ApiMailer`. The process holds no SMTP
configuration of its own; `build_mailer` reads `BUNYIP_MAILER_URL`,
`BUNYIP_MAILER_CLIENT_ID` and `BUNYIP_MAILER_CLIENT_SECRET` directly from env
(not from the `MailerConfig` the caller passed in, since those three fields
are not part of it) and constructs `ApiMailer` from them. Sending a message is
one HTTPS request: `POST {BUNYIP_MAILER_URL}/v1/mailer/send`, `Authorization:
Basic` built from the client id/secret pair, a JSON body of `{to, subject,
text, html}`. Bunyip owns the SMTP infrastructure and the verified sending
domain on the other end of that call; this process never sees an SMTP socket.
A `429` response (Bunyip's per-calling-app rate limit) and any other non-2xx
response both come back as `AppError::external_service("bunyip-mailer", ..)`,
naming the relay so a boot or send failure is never mistaken for a local SMTP
problem.

Any of the three `BUNYIP_MAILER_*` keys missing while `MAIL_PROVIDER=bunyip`
is selected is a boot-time `AppError::Configuration` naming the missing key;
there is no silent fallback to `log` or `smtp`; an operator who asks for the
relay and misconfigures it finds out at startup, not at the first unsent
password-reset email.

## What does not change between the three

Composition: the subject and body text built by `compose_invoice_sent`,
`compose_invoice_reminder`, and the rest of `src/utils/email.rs`'s templates
are identical regardless of which `Mailer` eventually sends them. Only the
transport differs; see [Mail
transport](self-hosted-vs-saas.md#mail-transport) for how this sits alongside
the broader self-hosted/SaaS split.
