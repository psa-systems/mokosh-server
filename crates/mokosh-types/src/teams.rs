//! Team models and types (PMS-791 / MAPPS-461).
//!
//! Teams are sub-groups of users inside one tenant. `teams` and
//! `team_members` tables have existed since migration 003 but were dormant
//! until this ticket added the module. See docs/mokosh-orgs/00-blueprint.md.
//!
//! Regex-shaped validation (color, member role) lives on the service side
//! rather than as `validator` derives here, so this crate keeps its lean
//! dependency footprint (no `regex` / `once_cell` needed just to compile).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// A team row. Returned by every endpoint that reads a team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub manager_id: Option<Uuid>,
    pub color: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A `team_members` row, projected verbatim from the DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub tenant_id: Uuid,
    pub team_id: Uuid,
    pub user_id: Uuid,
    /// `"leader"` or `"member"`. String rather than enum on the wire so
    /// server-side validation can 400 on unknowns with a `field` hint.
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// A member row joined to the corresponding `users` row so the client
/// can render name / email without a second round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMemberWithUser {
    pub user_id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub avatar_url: Option<String>,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// Envelope for `GET /api/v1/teams/{id}?include=members`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamWithMembers {
    pub team: Team,
    pub members: Vec<TeamMemberWithUser>,
}

/// Request body for `POST /api/v1/teams`.
///
/// `color` shape (`^#[0-9A-Fa-f]{6}$`) is enforced in
/// `TeamsService::create_team` via `validate_hex_color`, not by a
/// `validator` regex derive here; keeps this crate free of a `regex`
/// dep just for two field validators (security review F5).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateTeamRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub manager_id: Option<Uuid>,
    pub color: Option<String>,
}

/// Request body for `PUT /api/v1/teams/{id}`. Every field optional; omitted
/// fields are left unchanged. `null` on nullable fields clears the column.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTeamRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub manager_id: Option<Uuid>,
    pub color: Option<String>,
    pub is_active: Option<bool>,
}

/// Request body for `POST /api/v1/teams/{id}/members`.
///
/// `role` (when present) must be `"leader"` or `"member"`; validated in
/// `TeamsService::add_member`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct AddTeamMemberRequest {
    pub user_id: Uuid,
    pub role: Option<String>,
}

/// Request body for `PUT /api/v1/teams/{id}/members/{user_id}`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateTeamMemberRoleRequest {
    pub role: String,
}
