//! PMS-730: client request forms delivered by magic link.
//!
//! An MSP user issues a link scoped to one client and one form definition; the
//! client fills it in without logging in; the submission becomes a ticket
//! attributed to that client and carrying the KB article describing how to
//! perform the change.
//!
//! The emailed token is `{token_id}.{secret}`, with only the Argon2 hash of
//! the secret stored, so resolution is a primary-key lookup plus exactly one
//! verify. See migration 101 for why this does not copy the
//! `portal_setup_tokens` shape, whose salted hash forces a scan.

use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use super::models::{
    IssueRequestLinkRequest, PublicFormField, PublicFormResponse, PublicSubmissionReceipt,
    RequestLinkResponse, ResolvedRequestToken,
};
use super::service::FormsService;
use crate::modules::auth::TenantId;
use crate::modules::tenants::OrgIdentity;
use crate::utils::crypto::{generate_token, hash_password, verify_password};
use crate::utils::email::salutation;
use crate::utils::error::{AppError, AppResult};
use crate::utils::html::{html_escape, urlencoded};

/// PMS-730 assumes a 7 day expiry, revisable once the flow has been used in
/// anger. Long enough for a client to get to it after a weekend, short enough
/// that a link forwarded onward goes stale.
const REQUEST_LINK_TTL_DAYS: i64 = 7;

/// Everything the `forms.request_link` template renders.
///
/// A struct rather than a row of positional `&str`s: the fields are five
/// strings in a row, so a transposed pair would email the tenant's name as the
/// form's and nothing would fail. Named fields make that impossible to write
/// by accident.
struct RequestLinkEmail<'a> {
    recipient_email: &'a str,
    display_name: &'a str,
    form_name: &'a str,
    /// PMS-761: the MSP as the client sees them: name (MAPPS-425, without
    /// which the client received a literal `{{tenant_name}}`), contact details
    /// for when the form defines none (MAPPS-429), and the logo.
    org: &'a OrgIdentity,
    /// PMS-748: the MSP user who issued this link. A client receiving a
    /// request for personal details is entitled to a person's name, not just
    /// an organisation's.
    sender_name: &'a str,
    /// PMS-748: the client company the link was issued against, so the closing
    /// line can say who the message was intended for. It replaces "if you were
    /// not expecting this, you can ignore this message", which gave a
    /// recipient nothing to check.
    company_name: &'a str,
    /// PMS-748: the definition's optional contact details, which win over the
    /// organisation's general ones when the form routes somewhere unusual.
    contact_info: Option<&'a str>,
    form_link: &'a str,
    expires_at: chrono::DateTime<Utc>,
}

impl FormsService {
    /// Mint a link for `company_id` against `form_definition_id` and queue the
    /// email. Returns the row (never the token, which only the recipient
    /// should ever hold; it exists in cleartext just long enough to render the
    /// message).
    ///
    /// The link is scoped to the company at ISSUE time. Nothing the submitter
    /// later types can change which company the resulting ticket lands on, so
    /// a forwarded link cannot file a request against someone else.
    pub async fn issue_request_link(
        &self,
        tenant_id: TenantId,
        created_by: Uuid,
        req: &IssueRequestLinkRequest,
        app_url: &str,
    ) -> AppResult<RequestLinkResponse> {
        let definition = self.get(tenant_id, req.form_definition_id).await?;
        if !definition.is_active {
            return Err(AppError::Conflict(
                "This form has been retired and cannot be sent to a client.".to_string(),
            ));
        }

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Company and contact are verified inside the tenant transaction, so a
        // caller cannot address a link at another tenant's company by id.
        let company_name: Option<String> =
            sqlx::query_scalar("SELECT name FROM companies WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(req.company_id)
                .fetch_optional(&mut *tx)
                .await?;
        let company_name = company_name.ok_or_else(|| AppError::NotFound("Company".to_string()))?;

        // MAPPS-425: the seeded subject is
        // `{{form_name}} request form from {{tenant_name}}`, and the context
        // never carried `tenant_name`, so clients received a literal
        // `{{tenant_name}}`. Supplied here rather than fixed by a new
        // migration: `101_form_request_tokens.sql` is already applied
        // everywhere and immutable, so filling the value repairs every tenant
        // that already holds the seeded template. Read inside the tenant
        // transaction, matching `InvitationsService`.
        // MAPPS-429: branding rides along with the name, in the same read, so
        // the contact line and the logo cannot describe a different tenant than
        // the one the message says it is from. PMS-761 folds both into
        // `OrgIdentity`; read here rather than through `OrgIdentity::load` so
        // it stays inside the transaction that already has the row.
        let (tenant_name, branding): (String, serde_json::Value) =
            sqlx::query_as("SELECT name, branding FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        let org = OrgIdentity::from_row(tenant_name, branding);
        let tenant_name = org.name().to_string();

        // PMS-748: the person doing the asking. Read in the same transaction
        // as the tenant and the company, so the email is composed from one
        // consistent picture of who is sending what to whom.
        let sender: Option<(String, String, String)> = sqlx::query_as(
            "SELECT first_name, last_name, email FROM users WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(created_by)
        .fetch_optional(&mut *tx)
        .await?;
        let sender_name = sender
            .map(|(first, last, email)| sender_display_name(&first, &last, &email))
            .unwrap_or_else(|| tenant_name.clone());

        // Resolve the addressee. An explicit contact supplies the address and
        // the name; otherwise the caller must give an email outright. PMS-774:
        // an unknown or blank name stays blank here, and `salutation` decides
        // how the message opens.
        let (contact_id, recipient_email, display_name) = match req.contact_id {
            Some(contact_id) => {
                let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
                    "SELECT email, first_name FROM contacts WHERE tenant_id = $1 AND id = $2",
                )
                .bind(tenant_id)
                .bind(contact_id)
                .fetch_optional(&mut *tx)
                .await?;
                let (email, first_name) =
                    row.ok_or_else(|| AppError::NotFound("Contact".to_string()))?;
                let email = req.recipient_email.clone().or(email).ok_or_else(|| {
                    AppError::BadRequest(
                        "That contact has no email address; supply recipient_email".to_string(),
                    )
                })?;
                (Some(contact_id), email, first_name.unwrap_or_default())
            }
            None => {
                let email = req.recipient_email.clone().ok_or_else(|| {
                    AppError::BadRequest("Supply either contact_id or recipient_email".to_string())
                })?;
                (None, email, String::new())
            }
        };

        let token_id = Uuid::new_v4();
        let secret = generate_token(64);
        let token_hash = hash_password(&secret)?;
        let expires_at = Utc::now() + Duration::days(REQUEST_LINK_TTL_DAYS);

        sqlx::query(
            "INSERT INTO form_request_tokens \
               (id, tenant_id, form_definition_id, company_id, contact_id, \
                recipient_email, token_hash, expires_at, created_by_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(token_id)
        .bind(tenant_id)
        .bind(req.form_definition_id)
        .bind(req.company_id)
        .bind(contact_id)
        .bind(&recipient_email)
        .bind(&token_hash)
        .bind(expires_at)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // Delivery is best-effort and happens AFTER the commit, mirroring the
        // portal setup-link path: a failed send must not roll back the token,
        // because the row is what makes a resend possible.
        let token = format!("{token_id}.{secret}");
        let form_link = format!("{}/request-forms/{}", app_url.trim_end_matches('/'), token);
        self.queue_request_link_email(
            tenant_id,
            RequestLinkEmail {
                recipient_email: &recipient_email,
                display_name: &display_name,
                form_name: &definition.name,
                org: &org,
                sender_name: &sender_name,
                company_name: &company_name,
                contact_info: definition.contact_info.as_deref(),
                form_link: &form_link,
                expires_at,
            },
        )
        .await;

        Ok(RequestLinkResponse {
            id: token_id,
            form_definition_id: req.form_definition_id,
            form_name: definition.name,
            company_id: req.company_id,
            company_name,
            contact_id,
            recipient_email,
            expires_at,
            used_at: None,
            submission_id: None,
        })
    }

    async fn queue_request_link_email(&self, tenant_id: TenantId, mail: RequestLinkEmail<'_>) {
        let RequestLinkEmail {
            recipient_email,
            display_name,
            form_name,
            org,
            sender_name,
            company_name,
            contact_info,
            form_link,
            expires_at,
        } = mail;
        let Some(notify) = self.notifications.as_ref() else {
            tracing::warn!(
                "no notifications dispatcher wired; request-link token persisted but no message queued",
            );
            return;
        };
        let (abuse_notice, abuse_notice_html) =
            abuse_notice(self.abuse_contact_email.as_deref(), form_name);
        let context = json!({
            "recipient_email": recipient_email,
            // PMS-774: the greeting word comes from the template via
            // `salutation`; `display_name` stays the bare name so a tenant
            // still holding a customised template that names it keeps
            // rendering rather than showing literal braces.
            "salutation": salutation(display_name),
            "display_name": display_name,
            "form_name": form_name,
            // MAPPS-425: the seeded subject asks for this; without it the
            // client sees the placeholder itself.
            "tenant_name": org.name(),
            // PMS-748: every key below is supplied unconditionally, including
            // the two that can be empty. `render_template` leaves an
            // unresolved key as literal braces in the delivered message, so
            // "omit the key when there is nothing to say" is not available:
            // the value has to be an empty string instead.
            "sender_name": sender_name,
            "company_name": company_name,
            "contact_line": org.contact_line("Questions about this request?", contact_info),
            "logo_html": org.logo_html(self.public_api_base.as_deref()),
            "abuse_notice": abuse_notice,
            "abuse_notice_html": abuse_notice_html,
            "form_link": form_link,
            "expires_on": expires_at.format("%Y-%m-%d").to_string(),
        });
        match notify
            .dispatch(tenant_id, "forms.request_link", &context)
            .await
        {
            Ok(_) => tracing::info!(form_name, "request-form link queued"),
            Err(e) => tracing::warn!(
                error = ?e,
                "request-link email dispatch failed; token persisted so the link can be resent",
            ),
        }
    }

    /// Resolve a presented token to the tenant, company and form behind it.
    ///
    /// Status contract, deliberately the same as the portal setup token's so a
    /// guessed token cannot be told from a stale one:
    ///
    /// - valid, unused, unexpired -> `Ok`
    /// - already submitted        -> `Gone` (410)
    /// - expired                  -> `BadRequest` (400)
    /// - malformed or no match    -> `BadRequest` (400)
    pub async fn resolve_request_token(&self, token: &str) -> AppResult<ResolvedRequestToken> {
        let invalid = || AppError::BadRequest("Invalid or expired request link".to_string());

        let (token_id, secret) = token.split_once('.').ok_or_else(invalid)?;
        if secret.is_empty() {
            return Err(invalid());
        }
        let token_id = Uuid::parse_str(token_id).map_err(|_| invalid())?;

        let row = sqlx::query_as::<_, TokenRow>(
            "SELECT tenant_id, form_definition_id, company_id, contact_id, token_hash, \
                        used_at, expires_at, created_by_id \
                 FROM form_request_tokens WHERE id = $1",
        )
        .bind(token_id)
        // SAFETY (PMS-285 / PMS-730): pre-auth, single-use request-link
        // resolution. The tenant is what this lookup RESOLVES, so there is
        // no `app.current_tenant` GUC to set beforehand; the row is found by
        // its own primary key and its secret is verified below before
        // anything is returned. `form_request_tokens` is RLS-covered
        // (migration 101) and would fail this lookup closed on the
        // unprivileged app pool, so it runs on the BYPASSRLS migrator pool,
        // exactly as portal setup-token redemption does. Every subsequent
        // query is tenant-scoped via begin_with_tenant.
        .fetch_optional(self.db.migrator_pool())
        .await?;

        let row = row.ok_or_else(invalid)?;

        if !verify_password(secret, &row.token_hash)? {
            return Err(invalid());
        }
        if row.used_at.is_some() {
            return Err(AppError::Gone(
                "This request link has already been submitted".to_string(),
            ));
        }
        if row.expires_at <= Utc::now() {
            return Err(invalid());
        }
        let TokenRow {
            tenant_id,
            form_definition_id,
            company_id,
            contact_id,
            created_by_id,
            ..
        } = row;

        Ok(ResolvedRequestToken {
            token_id,
            tenant_id: TenantId::from_trusted(tenant_id),
            form_definition_id,
            company_id,
            contact_id,
            created_by_id,
        })
    }

    /// The client-facing view of a form: enough to render and validate the
    /// inputs, and nothing else. No ids of the tenant's other records, no
    /// author, no timestamps, and no KB article (which is an internal
    /// procedure for whoever works the ticket, not something the client is
    /// entitled to read).
    pub async fn public_form_for_token(
        &self,
        resolved: &ResolvedRequestToken,
    ) -> AppResult<PublicFormResponse> {
        let definition = self
            .get(resolved.tenant_id, resolved.form_definition_id)
            .await?;
        // PMS-748: who is asking. The page is reached from an email by someone
        // with no account here, so it has to carry its own attribution rather
        // than relying on the message that linked to it still being open.
        let org = OrgIdentity::load(&self.db, resolved.tenant_id).await?;
        // MAPPS-429: the form's own contact wins; the organisation's is the
        // fallback, so an MSP sets a service-desk number once instead of on
        // every definition.
        //
        // PMS-776: framed either way. The form-supplied branch used to be
        // returned raw, so only one of the two branches of this one field told
        // the client who was asking.
        let contact_info = org.phrase_with(definition.contact_info.as_deref());
        Ok(PublicFormResponse {
            name: definition.name,
            description: definition.description,
            tenant_name: org.name().to_string(),
            contact_info,
            logo_url: org.logo_path().map(str::to_string),
            rules: definition.rules,
            fields: definition
                .fields
                .into_iter()
                .map(|f| PublicFormField {
                    name: f.name,
                    label: f.label,
                    help_text: f.help_text,
                    field_type: f.field_type,
                    is_required: f.is_required,
                    min_length: f.min_length,
                    max_length: f.max_length,
                    options: f.options,
                    date_not_in_past: f.date_not_in_past,
                })
                .collect(),
        })
    }
}

impl FormsService {
    /// Redeem a resolved link: validate the payload against the definition,
    /// store the submission, create the ticket, and mark the link used.
    ///
    /// Ordering matters. The submission and the ticket are created first and
    /// the token is marked used LAST, inside the same transaction, so a
    /// failure anywhere rolls the whole thing back and the client can retry
    /// with the link still live. Marking the token first would burn a
    /// single-use link on a request that never produced a ticket.
    pub async fn submit_via_request_link(
        &self,
        resolved: &ResolvedRequestToken,
        payload: &serde_json::Value,
    ) -> AppResult<PublicSubmissionReceipt> {
        let tenant_id = resolved.tenant_id;
        let definition = self.get(tenant_id, resolved.form_definition_id).await?;
        if !definition.is_active {
            return Err(AppError::Conflict(
                "This form has been retired and is no longer accepting submissions.".to_string(),
            ));
        }

        // Same validator the authenticated surface uses, so a client and an
        // agent get identical rules and identical per-field errors.
        let normalised = super::validation::validate_submission(
            &definition.fields,
            &definition.rules,
            payload,
            Utc::now().date_naive(),
        )?;

        let submission_id = Uuid::new_v4();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO form_submissions \
               (id, tenant_id, form_definition_id, payload, submitted_by_contact_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(submission_id)
        .bind(tenant_id)
        .bind(resolved.form_definition_id)
        .bind(serde_json::Value::Object(normalised.clone()))
        .bind(resolved.contact_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let Some(tickets) = self.tickets.as_ref() else {
            return Err(AppError::Internal(
                "no ticket service wired into the forms service".to_string(),
            ));
        };

        // Company and contact come from the TOKEN, never from the payload, so
        // a forwarded link cannot file a request against another company. The
        // acting user is the MSP user who issued the link: the submitter is a
        // client with no `users` row, and `tickets.created_by_id` is NOT NULL.
        let request = mokosh_types::tickets::CreateTicketRequest {
            title: format!(
                "{}: {}",
                definition.name,
                summarise(&definition, &normalised)
            ),
            description: Some(render_answers(&definition, &normalised)),
            company_id: resolved.company_id,
            contact_id: resolved.contact_id,
            source: mokosh_types::tickets::TicketSource::Portal,
            // PMS-730 AC: the ticket carries the article describing how to
            // perform this change, selected by the request type. The form
            // definition IS the request type, so the mapping is its column.
            procedure_kb_article_id: definition.kb_article_id,
            custom_fields: serde_json::json!({}),
            ..Default::default()
        };
        let ctx = crate::modules::audit::AuditCtx::system(tenant_id.get());
        let ticket = tickets
            .create_ticket(tenant_id, resolved.created_by_id, &request, &ctx)
            .await?;

        // Link the chain and burn the token together, so a link is only ever
        // spent once a ticket actually exists.
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query("UPDATE form_submissions SET ticket_id = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(submission_id)
            .bind(ticket.id)
            .execute(&mut *tx)
            .await?;
        let burned = sqlx::query(
            "UPDATE form_request_tokens SET used_at = NOW(), submission_id = $3 \
             WHERE tenant_id = $1 AND id = $2 AND used_at IS NULL",
        )
        .bind(tenant_id)
        .bind(resolved.token_id)
        .bind(submission_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;

        // `used_at IS NULL` in the UPDATE is the race guard: two submissions
        // arriving together both pass the earlier resolve check, but only one
        // updates a row. The loser is reported as already submitted rather
        // than quietly accepted.
        if burned == 0 {
            return Err(AppError::Gone(
                "This request link has already been submitted".to_string(),
            ));
        }

        Ok(PublicSubmissionReceipt {
            ticket_number: ticket.ticket_number,
        })
    }
}

/// PMS-748: the name a client should see for the MSP user who sent this.
///
/// Falls back to the same email-derived name the JIT user insert uses, which
/// already refuses to derive one from a UUID local part or mokosh's own
/// placeholder domain. Both name columns are NOT NULL but may hold empty
/// strings, so the blank case is real rather than theoretical.
fn sender_display_name(first_name: &str, last_name: &str, email: &str) -> String {
    let full = format!("{} {}", first_name.trim(), last_name.trim());
    let full = full.trim();
    if !full.is_empty() {
        return full.to_string();
    }
    let (first, last) = crate::modules::auth::synthetic_name_from_email(email);
    format!("{first} {last}")
}

/// PMS-748: the report-abuse line, in text and HTML flavours, or two empty
/// strings when the deployment has not configured an address.
///
/// The HTML flavour carries its own `<p>` wrapper. `render_template` has no
/// conditionals, so a wrapper written into the template would leave an empty
/// paragraph dangling on every deployment without an abuse address; composing
/// the whole element here is what lets the line vanish completely.
///
/// The address is escaped for both the attribute and the text, because it
/// arrives from deployment configuration rather than from this crate.
fn abuse_notice(abuse_contact_email: Option<&str>, form_name: &str) -> (String, String) {
    let Some(address) = abuse_contact_email.map(str::trim).filter(|a| !a.is_empty()) else {
        return (String::new(), String::new());
    };
    let text = format!("\n\nDid not expect this? Report it to {address}.");
    let escaped = html_escape(address);
    let subject = urlencoded(&format!("Unexpected request form: {form_name}"));
    let html = format!(
        "<p>Did not expect this? <a href=\"mailto:{escaped}?subject={subject}\">Report it</a>.</p>"
    );
    (text, html)
}

/// A one-line summary for the ticket title, taken from the first answered text
/// field in display order. Falls back to the company-agnostic form name alone
/// when the form has no text field, which keeps the title deterministic rather
/// than guessing at semantics the definition does not declare.
pub(super) fn summarise(
    definition: &super::models::FormDefinitionResponse,
    answers: &serde_json::Map<String, serde_json::Value>,
) -> String {
    definition
        .fields
        .iter()
        .find_map(|f| {
            matches!(f.field_type, super::models::FieldType::Text)
                .then(|| answers.get(&f.name).and_then(|v| v.as_str()))
                .flatten()
        })
        .unwrap_or("client request")
        .to_string()
}

/// Render the answers as the ticket description, in the form's own field
/// order and using its labels, so whoever works the ticket reads what the
/// client saw rather than raw payload keys.
///
/// PMS-747: emitted as a Markdown list, because the ticket description is
/// RENDERED as Markdown by the SPA. Separating the answers with plain newlines
/// put every one of them in a single paragraph, so a three-field submission
/// arrived as `First name: David Last name: Randall Phone number: 919...` on
/// one run-on line, and got worse the more the form asked for.
///
/// A textarea answer carries its own newlines. Those become hard breaks
/// (two trailing spaces) and the continuation is indented into the list item,
/// so the client's paragraphing survives instead of collapsing the same way.
///
/// PMS-729 phase 2 §7 slice B / I8: `pub(super)` so the portal form-submit
/// handler in `super::service::submit_from_portal` can call this too - the
/// portal path renders the same description shape as the request-link path.
pub(super) fn render_answers(
    definition: &super::models::FormDefinitionResponse,
    answers: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut out = String::new();
    for field in &definition.fields {
        let Some(value) = answers.get(&field.name) else {
            continue;
        };
        let rendered = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(b) => if *b { "Yes" } else { "No" }.to_string(),
            other => other.to_string(),
        };
        let rendered = rendered.replace('\n', "  \n  ");
        out.push_str(&format!("- **{}:** {}\n", field.label, rendered));
    }
    out
}

impl FormsService {
    /// Links this tenant has issued, newest first, optionally narrowed to one
    /// client. Never includes the token: the row is an audit trail of what was
    /// sent and whether it has been used, not a way to recover a credential
    /// that only the recipient should hold.
    pub async fn list_request_links(
        &self,
        tenant_id: TenantId,
        company_id: Option<Uuid>,
    ) -> AppResult<Vec<RequestLinkResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, LinkRow>(
            "SELECT t.id, t.form_definition_id, d.name AS form_name, t.company_id, \
                    c.name AS company_name, t.contact_id, t.recipient_email, \
                    t.expires_at, t.used_at, t.submission_id \
             FROM form_request_tokens t \
             JOIN form_definitions d ON d.id = t.form_definition_id \
             JOIN companies c ON c.id = t.company_id \
             WHERE t.tenant_id = $1 AND ($2::uuid IS NULL OR t.company_id = $2) \
             ORDER BY t.created_at DESC",
        )
        .bind(tenant_id)
        .bind(company_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}

/// The token row as resolution reads it. A struct rather than a tuple so the
/// field meanings survive the read.
#[derive(sqlx::FromRow)]
struct TokenRow {
    tenant_id: Uuid,
    form_definition_id: Uuid,
    company_id: Uuid,
    contact_id: Option<Uuid>,
    token_hash: String,
    used_at: Option<chrono::DateTime<Utc>>,
    expires_at: chrono::DateTime<Utc>,
    created_by_id: Uuid,
}

#[derive(sqlx::FromRow)]
struct LinkRow {
    id: Uuid,
    form_definition_id: Uuid,
    form_name: String,
    company_id: Uuid,
    company_name: String,
    contact_id: Option<Uuid>,
    recipient_email: String,
    expires_at: chrono::DateTime<Utc>,
    used_at: Option<chrono::DateTime<Utc>>,
    submission_id: Option<Uuid>,
}

impl From<LinkRow> for RequestLinkResponse {
    fn from(r: LinkRow) -> Self {
        Self {
            id: r.id,
            form_definition_id: r.form_definition_id,
            form_name: r.form_name,
            company_id: r.company_id,
            company_name: r.company_name,
            contact_id: r.contact_id,
            recipient_email: r.recipient_email,
            expires_at: r.expires_at,
            used_at: r.used_at,
            submission_id: r.submission_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::forms::models::{FieldType, FormDefinitionResponse, FormFieldResponse};

    fn field(name: &str, label: &str, field_type: FieldType) -> FormFieldResponse {
        FormFieldResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            label: label.to_string(),
            help_text: None,
            field_type,
            is_required: false,
            min_length: None,
            max_length: None,
            options: None,
            date_not_in_past: false,
            sort_order: 0,
        }
    }

    fn definition(fields: Vec<FormFieldResponse>) -> FormDefinitionResponse {
        FormDefinitionResponse {
            id: Uuid::nil(),
            name: "New user".to_string(),
            slug: "new-user".to_string(),
            description: None,
            contact_info: None,
            kb_article_id: None,
            kb_article_title: None,
            rules: Vec::new(),
            is_active: true,
            created_by_id: Uuid::nil(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            fields,
        }
    }

    /// PMS-748: the MSP is always named. Only the channel is optional.
    #[test]
    fn an_unconfigured_abuse_contact_emits_no_line() {
        assert_eq!(
            abuse_notice(None, "New user"),
            (String::new(), String::new())
        );
        assert_eq!(
            abuse_notice(Some("  "), "New user"),
            (String::new(), String::new())
        );
    }

    /// The HTML flavour carries its own `<p>`, because `render_template` has no
    /// conditionals and a wrapper in the template would leave an empty
    /// paragraph on every deployment that has not configured an address.
    #[test]
    fn a_configured_abuse_contact_composes_both_flavours() {
        let (text, html) = abuse_notice(Some("abuse@example.com"), "New user & leaver");

        assert_eq!(
            text,
            "\n\nDid not expect this? Report it to abuse@example.com."
        );
        assert_eq!(
            html,
            "<p>Did not expect this? <a href=\"mailto:abuse@example.com?subject=Unexpected%20request%20form%3A%20New%20user%20%26%20leaver\">Report it</a>.</p>",
            "an unencoded space or ampersand in the form name would truncate the mailto or escape the attribute"
        );
    }

    /// PMS-748: the sender is a person, and the fallback is the same
    /// email-derived name the JIT user insert uses rather than a second copy of
    /// those rules.
    #[test]
    fn the_sender_is_named_from_the_user_or_their_email() {
        assert_eq!(
            sender_display_name("David", "Randall", "david@example.com"),
            "David Randall"
        );
        assert_eq!(
            sender_display_name("  ", "", "dana.reid@example.com"),
            "Dana Reid",
            "both name columns are NOT NULL but may hold empty strings"
        );
    }

    /// PMS-747: the SPA renders a ticket description as Markdown, where a plain
    /// newline is not a break. Joining answers with one meant a three-field
    /// submission arrived as a single run-on line.
    #[test]
    fn each_answer_is_its_own_line_in_the_rendered_description() {
        let def = definition(vec![
            field("first_name", "First name", FieldType::Text),
            field("last_name", "Last name", FieldType::Text),
            field("needs_laptop", "Needs a laptop", FieldType::Boolean),
        ]);
        let answers = serde_json::json!({
            "first_name": "David",
            "last_name": "Randall",
            "needs_laptop": true,
        });

        let rendered = render_answers(&def, answers.as_object().expect("object"));

        assert_eq!(
            rendered,
            "- **First name:** David\n- **Last name:** Randall\n- **Needs a laptop:** Yes\n"
        );
    }

    /// A textarea answer carries the client's own paragraphing, which must not
    /// collapse for the same reason the answers themselves must not.
    #[test]
    fn a_multi_line_answer_keeps_its_breaks() {
        let def = definition(vec![field("detail", "Detail", FieldType::Textarea)]);
        let answers = serde_json::json!({ "detail": "Line one\nLine two" });

        let rendered = render_answers(&def, answers.as_object().expect("object"));

        assert_eq!(
            rendered, "- **Detail:** Line one  \n  Line two\n",
            "two trailing spaces are the Markdown hard break; the indent keeps the continuation in the list item"
        );
    }

    /// The form's field order is the order the client answered in, and a field
    /// left blank is dropped rather than rendered as an empty line.
    #[test]
    fn unanswered_fields_are_left_out_and_order_follows_the_form() {
        let def = definition(vec![
            field("first_name", "First name", FieldType::Text),
            field("nickname", "Nickname", FieldType::Text),
            field("last_name", "Last name", FieldType::Text),
        ]);
        let answers = serde_json::json!({ "last_name": "Randall", "first_name": "David" });

        let rendered = render_answers(&def, answers.as_object().expect("object"));

        assert_eq!(
            rendered,
            "- **First name:** David\n- **Last name:** Randall\n"
        );
    }
}
