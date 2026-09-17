//! MAPPS-877: unified members model.
//!
//! One row per person with access to a tenant. Serves the People pane
//! of `/settings/members`, and the underlying user set of the Teams
//! pane's user picker. A row is one of:
//!
//! - `MemberRow::User` for a native `users` row inside this tenant.
//!   `placed_by_grant_id = Some(_)` tags it as a guest that has signed
//!   in (BUNYIP-674 JIT placement wrote the users row); the SPA reads
//!   the effective role from the grant then, not from `users.role`,
//!   which is a reprojection PMS-1162 keeps in sync.
//! - `MemberRow::UnplacedGuest` for a grant with no matching `users`
//!   row: the invitee accepted the grant but has not made a request
//!   to this mokosh yet, so no placement ran. Rendered dimmed with
//!   an "Awaiting first sign-in" chip.
//!
//! `TeamChip` is what a client renders as a compact team indicator on
//! a `User` row.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One row on the People pane. See module docs for the variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemberRow {
    /// A native `users` row in this tenant. Placed guests appear here
    /// with `placed_by_grant_id = Some(_)`.
    User {
        user_id: Uuid,
        email: String,
        first_name: String,
        last_name: String,
        role: String,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_login_at: Option<DateTime<Utc>>,
        #[serde(default)]
        team_memberships: Vec<TeamChip>,
        /// `Some(grant_id)` when this row was placed by a grant.
        /// `None` on a native user (owner or invited to their own
        /// tenant).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        placed_by_grant_id: Option<Uuid>,
    },
    /// A grant with no matching `users` row yet. The invitee has
    /// accepted the grant but has not signed in to this mokosh
    /// (so nothing has run `place_grantee_caller`).
    UnplacedGuest {
        grant_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grantee_email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grantee_name: Option<String>,
        role: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        granted_at: Option<DateTime<Utc>>,
    },
}

/// Compact team indicator on a `User` row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamChip {
    pub team_id: Uuid,
    pub team_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// Envelope for `GET /api/v1/members`. `bunyip_reachable` rides on
/// the response so a SaaS-mode fan-out failure keeps the native list
/// visible with a top banner + retry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersResponse {
    pub rows: Vec<MemberRow>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    /// `true` when the grant fan-out succeeded (or is not applicable
    /// in standalone mode); `false` when SaaS bunyip is unreachable
    /// and the response contains natives only.
    pub bunyip_reachable: bool,
}
