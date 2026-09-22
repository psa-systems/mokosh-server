//! Re-export of the shared contacts DTOs from `mokosh-types`.
//! See [`mokosh_types`] and PMS-129.

pub use mokosh_types::contacts::*;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// mokosh-contact-login prompt 003: response body of
/// `POST /api/v1/contacts/{id}/grant-portal-access`. Carries the
/// Company's portal slug + the freshly minted setup link so the SPA
/// can display + copy-to-clipboard the URL (useful when the email
/// dispatch is delayed or the operator wants to hand-relay via chat).
///
/// mokosh-contact-login prompt 011 (PMS-928): also carries the
/// Company's 9-digit `portal_id` so the SPA can render "Portal ID:
/// 555556666" alongside the URL and the operator can dictate it over
/// the phone. Pinned to i64 to match `companies.portal_id BIGINT`.
///
/// PMS-1327: the setup token used to ride here as `setup_link` so the
/// SPA could paint the "Copy this link" affordance. That handed the
/// password-setup capability to anyone who could read the markup.
/// `setup_link` stays on the struct so the integration suite can
/// exercise the redemption flow it drives, but is `#[serde(skip)]` on
/// the response: the SPA never sees it, and the token reaches the
/// contact only through the registration email `send_grant_email`
/// dispatches. `password_email_queued` says whether that mail went so
/// the SPA can still distinguish a fresh grant from a role-only edit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalGrantOutcome {
    pub portal_slug: String,
    pub portal_id: i64,
    #[serde(default)]
    pub password_email_queued: bool,
    #[serde(skip)]
    pub setup_link: String,
}

#[cfg(test)]
mod portal_grant_outcome_serde_tests {
    use super::*;

    /// PMS-1327: the setup token is what sets the account password, so the
    /// SPA must never see it. The wire shape carries `portal_slug`,
    /// `portal_id` and `password_email_queued` only. Two guards, both
    /// failing loud: the serialized JSON must NOT hold the field, and it
    /// must NOT hold the token or the URL that carries it.
    #[test]
    fn serialised_outcome_does_not_leak_the_setup_link() {
        let outcome = PortalGrantOutcome {
            portal_slug: "acme".to_string(),
            portal_id: 555_556_666,
            password_email_queued: true,
            setup_link: "https://portal.example/portal/acme/set-password?token=c.SECRET"
                .to_string(),
        };
        let json = serde_json::to_string(&outcome).expect("serialise outcome");
        assert!(
            !json.contains("setup_link"),
            "PMS-1327: setup_link field must not reach the wire: {json}"
        );
        assert!(
            !json.contains("set-password"),
            "PMS-1327: the setup URL must not reach the wire: {json}"
        );
        assert!(
            !json.contains("SECRET"),
            "PMS-1327: the setup token must not reach the wire: {json}"
        );
        assert!(json.contains("\"portal_slug\":\"acme\""));
        assert!(json.contains("\"portal_id\":555556666"));
        assert!(json.contains("\"password_email_queued\":true"));
    }
}

/// mokosh-contact-login prompt 003: request body of
/// `POST /api/v1/contacts/{id}/grant-portal-access` +
/// `PUT /api/v1/contacts/{id}/portal-roles`. `role_ids` REPLACES any
/// prior assignment set (see `ContactService::grant_portal_access`).
#[derive(Debug, Clone, Deserialize)]
pub struct GrantPortalAccessRequest {
    pub role_ids: Vec<Uuid>,
}

/// mokosh-contact-login prompt 003: one row of
/// `GET /api/v1/portal-roles`. The SPA renders `capabilities` as a
/// checkbox list in the role-picker modal + label chips on the
/// contact edit page.
///
/// PMS-929 (prompt 012): `company_id` marks whether the role is
/// tenant-wide (`None`) or scoped to a single Company (`Some(id)`).
/// `#[serde(default)]` so a wire payload from a pre-migration client or
/// a hand-crafted test fixture without the field deserializes to
/// tenant-wide instead of erroring, which matches the historical
/// two-value shape and stays forward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalRoleSummary {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub is_builtin: bool,
    #[serde(default)]
    pub company_id: Option<Uuid>,
    /// MAPPS-635 E: count of contacts currently holding this role
    /// (via `contact_role_assignments`). Populated by the list
    /// handler so the Settings > Contact Roles table can render a
    /// real number in its CONTACTS column instead of the hard-coded
    /// "-". `serde(default)` so a wire payload from a pre-fix
    /// server still deserialises as `0`.
    #[serde(default)]
    pub contacts_count: i64,
}

/// PMS-1187: one access request, as staff read it.
///
/// Carries the note the contact wrote, because the whole point of asking is to
/// say why, and the MSP deciding needs it.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PortalAccessRequestRow {
    pub id: uuid::Uuid,
    pub contact_id: uuid::Uuid,
    pub company_id: Option<uuid::Uuid>,
    pub area: String,
    pub note: Option<String>,
    /// `open`, `granted`, `declined` or `withdrawn`.
    pub status: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub resolved_by_id: Option<uuid::Uuid>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// PMS-1187: how staff answer one.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ResolveAccessRequest {
    /// `true` grants the area's built-in role and closes the request; `false`
    /// closes it without granting. No third value: a request left open is left
    /// open by not calling this.
    pub grant: bool,
}
