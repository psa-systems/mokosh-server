//! PMS-761: who the MSP is, as a client sees them.
//!
//! An organisation's name, the person a client should ask for, the ways to
//! reach them, and the logo. Collected at onboarding (`/onboarding/profile`),
//! editable under Settings, Organization, and stored on the tenant row: the
//! name in `tenants.name`, the rest in `tenants.branding`.
//!
//! This lives here, shared, rather than beside any one email. It started as
//! private helpers in `modules::forms::request_links` (MAPPS-429, PMS-748,
//! PMS-755), which is why every other client-facing message mokosh sends was
//! anonymous: the quote, the invoice and the ticket-note emails could not
//! reach the wording, so they said nothing. One loader and one set of
//! sentences is the difference between "used across the system" and "used
//! once".
//!
//! Not gated on `multi-tenant` even though the rest of this module is: the
//! callers (quotes, billing, tickets, forms) are unconditional, and a
//! single-tenant build still has an organisation with a name.

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::utils::error::AppResult;
use crate::utils::html::html_escape;

/// The tenant-level identity, already normalised.
///
/// Every optional field has been trimmed and emptied-to-`None` on the way in,
/// so a caller never has to ask whether `Some("")` means set or unset. The
/// fields are private for that reason: the invariant is what makes the
/// sentence builders below safe to call blind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrgIdentity {
    name: String,
    contact_name: Option<String>,
    phone: Option<String>,
    /// PMS-755: the channel most clients reach for first. Optional even at
    /// onboarding, where the phone is required: demanding two channels before
    /// an MSP can finish setting up is a tax on the common case.
    email: Option<String>,
    /// The path the logo is served from, origin-relative
    /// (`/api/v1/public/tenants/{id}/logo`). Absolute only where a mail client
    /// needs it; see [`OrgIdentity::logo_html`].
    logo_path: Option<String>,
}

impl OrgIdentity {
    /// Build from a tenant name and its already-parsed branding.
    ///
    /// For callers that have read the tenant row for their own reasons and
    /// should not pay for a second round trip.
    pub fn from_branding(name: String, branding: &mokosh_types::tenants::TenantBranding) -> Self {
        Self {
            name: name.trim().to_string(),
            contact_name: clean(branding.support_contact_name.as_deref()),
            phone: clean(branding.support_phone.as_deref()),
            email: clean(branding.support_email.as_deref()),
            logo_path: clean(branding.logo_url.as_deref()),
        }
    }

    /// Build from the raw `(name, branding)` pair as the tenant row holds it.
    ///
    /// Branding that will not deserialise falls back to the default rather
    /// than failing the caller: a malformed key must not stop an invoice email
    /// going out, and the worst case is a message with no contact line, which
    /// is exactly where this feature started.
    pub fn from_row(name: String, branding: serde_json::Value) -> Self {
        let branding: mokosh_types::tenants::TenantBranding =
            serde_json::from_value(branding).unwrap_or_default();
        Self::from_branding(name, &branding)
    }

    /// Read the identity for one tenant.
    ///
    /// Tenant-scoped through `begin_with_tenant` so the RLS GUC is set; the
    /// identity in a client's email is always the identity of the tenant that
    /// owns the thing the email is about.
    pub async fn load(db: &Database, tenant_id: TenantId) -> AppResult<Self> {
        let mut tx = db.begin_with_tenant(tenant_id).await?;
        let (name, branding): (String, serde_json::Value) =
            sqlx::query_as("SELECT name, branding FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        drop(tx);
        Ok(Self::from_row(name, branding))
    }

    /// The organisation's name. Never empty in practice (the column is NOT
    /// NULL and onboarding requires it), and not worth an `Option` for the
    /// case where someone has saved whitespace.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn contact_name(&self) -> Option<&str> {
        self.contact_name.as_deref()
    }

    pub fn phone(&self) -> Option<&str> {
        self.phone.as_deref()
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    pub fn logo_path(&self) -> Option<&str> {
        self.logo_path.as_deref()
    }

    /// PMS-755: how to reach them, as a phrase that slots after a name.
    ///
    /// The preposition belongs to the channel, not to the sentence: "on" reads
    /// right before a number and wrong before an address. Built here rather
    /// than at the call sites so two messages cannot word the same two facts
    /// differently.
    pub fn channels(&self) -> Option<String> {
        match (self.phone(), self.email()) {
            (Some(p), Some(e)) => Some(format!("on {p} or by email at {e}")),
            (Some(p), None) => Some(format!("on {p}")),
            (None, Some(e)) => Some(format!("by email at {e}")),
            (None, None) => None,
        }
    }

    /// The contact as a bare phrase for a sentence that supplies its own verb,
    /// as the client's request-form page does ("Contact {phrase}.").
    ///
    /// Cannot start with a preposition, so it opens on the contact person, or
    /// on the organisation when no contact person is set, and never on a phone
    /// number.
    pub fn phrase(&self) -> Option<String> {
        let name = self.contact_name().unwrap_or(&self.name);
        match (self.channels(), self.contact_name().is_some()) {
            (Some(channels), _) => Some(format!("{name} {channels}")),
            (None, true) => Some(name.to_string()),
            (None, false) => None,
        }
    }

    /// PMS-776: the phrase with a per-message contact standing in for the
    /// organisation's own channels, as the request-form page needs.
    ///
    /// The same two branches as [`OrgIdentity::contact_line`], which is the
    /// point: the page used to return a form definition's own `contact_info`
    /// raw, so "call the service desk on 555-0100" reached a client with
    /// nothing saying whose service desk it is, while the fallback branch of
    /// the same field always named someone. `{name} at {info}` matches the
    /// email's override branch ("Contact {org} at {info}."), so one form with
    /// its own contact and one without produce the same shape.
    pub fn phrase_with(&self, override_info: Option<&str>) -> Option<String> {
        match clean(override_info) {
            Some(info) => Some(format!("{} at {}", self.name, info)),
            None => self.phrase(),
        }
    }

    /// PMS-748: the "how do I ask about this?" line, which is never empty.
    ///
    /// The organisation's NAME is not optional: a client asked to hand over
    /// details, approve a quote or pay an invoice is always told who is
    /// asking. The contact details are optional, so the sentence has several
    /// shapes rather than one shape with a hole in it. Nothing here promises a
    /// channel the deployment does not have: with no contact details at all it
    /// names the organisation rather than inviting a reply the from-address
    /// cannot accept.
    ///
    /// `opening` is the caller's question ("Questions about this invoice?"),
    /// because only the caller knows what the message is about. `override_info`
    /// is a per-message contact string that wins when present: a request form
    /// that routes somewhere unusual carries one, and it should not be
    /// overruled by the organisation's general service-desk number.
    pub fn contact_line(&self, opening: &str, override_info: Option<&str>) -> String {
        let org = &self.name;
        if let Some(info) = clean(override_info) {
            return format!("{opening} Contact {org} at {info}.");
        }
        match (self.contact_name(), self.channels()) {
            (Some(who), Some(channels)) => format!("{opening} Contact {who} at {org} {channels}."),
            (Some(who), None) => format!("{opening} Contact {who} at {org}."),
            (None, Some(channels)) => format!("{opening} Contact {org} {channels}."),
            (None, None) => format!("{opening} Contact {org}, who sent it to you."),
        }
    }

    /// MAPPS-429: the logo block for an HTML email, or an empty string.
    ///
    /// Empty whenever the deployment has not been told its own public base URL
    /// or the tenant has no logo. The template renderer has no conditionals, so
    /// an element that must sometimes disappear has to be composed whole here,
    /// and a key that can be empty must still always be supplied or the client
    /// receives literal braces.
    ///
    /// A mail client cannot resolve a relative `src`, so this is the one caller
    /// that needs an absolute URL. It is deliberately NOT built from `BASE_URL`
    /// or `SPA_BASE_URL`: on every deployed environment those are the apex and
    /// the SPA, and the logo is served by the API on a third host.
    pub fn logo_html(&self, public_api_base: Option<&str>) -> String {
        let (Some(base), Some(path)) = (clean(public_api_base), self.logo_path()) else {
            return String::new();
        };
        let src = format!("{}{}", base.trim_end_matches('/'), path);
        format!(
            "<p><img src=\"{}\" alt=\"{}\" style=\"max-height:56px;max-width:220px\"></p>",
            html_escape(&src),
            html_escape(&self.name)
        )
    }
}

/// Trim, and treat whitespace-only as absent. The one normalisation every
/// field needs, applied on the way in so no reader has to remember it.
fn clean(v: Option<&str>) -> Option<String> {
    v.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(contact: Option<&str>, phone: Option<&str>, email: Option<&str>) -> OrgIdentity {
        OrgIdentity {
            name: "Contoso IT".to_string(),
            contact_name: contact.map(str::to_string),
            phone: phone.map(str::to_string),
            email: email.map(str::to_string),
            logo_path: None,
        }
    }

    #[test]
    fn whitespace_only_branding_reads_as_unset() {
        let branding = mokosh_types::tenants::TenantBranding {
            support_contact_name: Some("  ".to_string()),
            support_phone: Some(String::new()),
            ..Default::default()
        };
        let id = OrgIdentity::from_branding("  Contoso IT  ".to_string(), &branding);
        assert_eq!(id.name(), "Contoso IT");
        assert_eq!(id.contact_name(), None);
        assert_eq!(id.phone(), None);
        // Nothing to offer, so nothing is offered, and the sentence still ends.
        assert_eq!(
            id.contact_line("Questions?", None),
            "Questions? Contact Contoso IT, who sent it to you."
        );
    }

    #[test]
    fn malformed_branding_still_yields_a_usable_identity() {
        // An invoice email must not be lost to a branding key of the wrong
        // type; the worst acceptable outcome is a message with no contact.
        let id =
            OrgIdentity::from_row("Contoso IT".to_string(), serde_json::json!("not-an-object"));
        assert_eq!(id.name(), "Contoso IT");
        assert_eq!(id.phrase(), None);
    }

    #[test]
    fn the_contact_line_names_the_org_in_every_shape() {
        let opening = "Questions about this invoice?";
        assert_eq!(
            org(Some("the service desk"), Some("555-0100"), Some("h@c.example"))
                .contact_line(opening, None),
            "Questions about this invoice? Contact the service desk at Contoso IT on 555-0100 or by email at h@c.example."
        );
        assert_eq!(
            org(Some("the service desk"), None, None).contact_line(opening, None),
            "Questions about this invoice? Contact the service desk at Contoso IT."
        );
        assert_eq!(
            org(None, None, Some("h@c.example")).contact_line(opening, None),
            "Questions about this invoice? Contact Contoso IT by email at h@c.example."
        );
        assert_eq!(
            org(None, None, None).contact_line(opening, None),
            "Questions about this invoice? Contact Contoso IT, who sent it to you."
        );
    }

    #[test]
    fn a_per_message_contact_wins_over_the_organisation_default() {
        assert_eq!(
            org(Some("the service desk"), Some("555-0100"), None).contact_line(
                "Questions about this request?",
                Some(" projects@c.example ")
            ),
            "Questions about this request? Contact Contoso IT at projects@c.example."
        );
    }

    #[test]
    fn the_phrase_never_opens_on_a_phone_number() {
        assert_eq!(
            org(None, Some("555-0100"), None).phrase().unwrap(),
            "Contoso IT on 555-0100"
        );
        assert_eq!(
            org(Some("Dana"), Some("555-0100"), None).phrase().unwrap(),
            "Dana on 555-0100"
        );
        assert_eq!(org(None, None, None).phrase(), None);
    }

    #[test]
    fn both_branches_of_the_form_pages_contact_line_name_the_organisation() {
        let org = org(None, Some("555-0100"), None);
        // A form definition carrying its own contact used to be returned raw.
        assert_eq!(
            org.phrase_with(Some(" call the service desk on 555-0199 ")),
            Some("Contoso IT at call the service desk on 555-0199".to_string())
        );
        // No definition contact: the shared phrase, unchanged.
        assert_eq!(org.phrase_with(None), org.phrase());
        assert_eq!(org.phrase_with(Some("   ")), org.phrase());
        // Both shapes open on a name, which is the finding.
        for phrase in [org.phrase_with(Some("555-0199")), org.phrase_with(None)] {
            assert!(
                phrase.expect("a phrase").starts_with("Contoso IT"),
                "a client is always told who is asking"
            );
        }
    }

    #[test]
    fn the_logo_block_needs_both_a_base_url_and_a_logo() {
        let mut id = org(None, None, None);
        assert_eq!(id.logo_html(Some("https://api.example")), "");
        id.logo_path = Some("/api/v1/public/tenants/x/logo".to_string());
        assert_eq!(id.logo_html(None), "");
        assert_eq!(id.logo_html(Some("   ")), "");
        assert_eq!(
            id.logo_html(Some("https://api.example/")),
            "<p><img src=\"https://api.example/api/v1/public/tenants/x/logo\" alt=\"Contoso IT\" style=\"max-height:56px;max-width:220px\"></p>"
        );
    }

    #[test]
    fn an_organisation_name_cannot_break_out_of_the_logo_markup() {
        let id = OrgIdentity {
            name: r#"A" onerror="x"#.to_string(),
            logo_path: Some("/logo".to_string()),
            ..Default::default()
        };
        let html = id.logo_html(Some("https://api.example"));
        assert!(
            html.contains("alt=\"A&quot; onerror=&quot;x\""),
            "the tenant-set name must be escaped: {html}"
        );
    }
}
