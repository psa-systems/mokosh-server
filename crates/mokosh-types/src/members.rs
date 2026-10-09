//! Unified members list (MAPPS-877 phase 1).
//!
//! `GET /api/v1/members` returns the merged list of native `users` + cross-
//! account grantees in one envelope so a UI can render "who has access to
//! this workspace" without reconciling two paginated feeds client-side.
//!
//! A placed grantee appears here twice-under-one-row: it is a native `users`
//! row (JIT-provisioned on first sign-in per BUNYIP-674) AND it has a live
//! `mokosh_bunyip_grants` row naming it as grantee. The server collapses
//! that pair into one `MemberRow::User` with `placed_by_grant_id = Some(_)`,
//! so the SPA renders "Guest" beside the name without a second lookup.
//!
//! A grant with no matching users row yet is an `UnplacedGuest`: the invitee
//! accepted the grant on bunyip but has not yet made a request to this
//! mokosh, so JIT placement has not run. Shown as "Awaiting first sign-in".

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One row in the merged members list.
///
/// `#[serde(tag = "kind")]` so the SPA can key off a single discriminant;
/// `snake_case` matches the rest of the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemberRow {
    /// A native `users` row in this tenant. Includes JIT-placed grantees
    /// who have signed in at least once; they are just users at that
    /// point, distinguishable only by `placed_by_grant_id`.
    User {
        user_id: Uuid,
        email: String,
        first_name: String,
        last_name: String,
        role: String,
        /// `active | inactive | pending`.
        status: String,
        last_login_at: Option<DateTime<Utc>>,
        /// Teams this user belongs to. Batched server-side.
        team_memberships: Vec<TeamChip>,
        /// `Some(grant_id)` when this users row was placed by a grant
        /// (BUNYIP-674 option B). The row is a native user AND has a
        /// grant; the SPA renders "Guest" beside the name and reads
        /// role from the grant, not the user.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        placed_by_grant_id: Option<String>,
    },
    /// A grant with no matching `users` row yet: invitee accepted the
    /// grant but has not yet made a request to this mokosh, so no JIT
    /// placement has run. Shown dimmed with "Awaiting first sign-in".
    UnplacedGuest {
        grant_id: String,
        grantee_email: Option<String>,
        grantee_name: Option<String>,
        role: String,
        granted_at: Option<DateTime<Utc>>,
    },
}

/// A team the user belongs to, kept to the fields the row chip renders.
/// Pulled from `teams` + `team_members` in one batched query, not one per
/// row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamChip {
    pub team_id: Uuid,
    pub team_name: String,
    pub color: Option<String>,
}

/// Envelope for `GET /api/v1/members`. `bunyip_reachable` lets the SPA
/// surface a "guest list unavailable" banner when the fan-out failed;
/// standalone mode (no cross-process call) always sets it `true` because
/// the read never left the process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MembersResponse {
    pub rows: Vec<MemberRow>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub bunyip_reachable: bool,
}
