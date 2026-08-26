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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalGrantOutcome {
    pub portal_slug: String,
    pub portal_id: i64,
    pub setup_link: String,
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
#[derive(Debug, Clone, Serialize)]
pub struct PortalRoleSummary {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub is_builtin: bool,
}
