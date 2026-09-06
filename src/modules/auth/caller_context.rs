//! mokosh-contact-login prompt 008: `CallerContext` + `RequireCallerContext`.
//!
//! A single enum that a dual-plane handler ("either a staff user OR a portal
//! contact may call this") reads instead of picking between `RequireAuth`
//! (staff) and `RequireContactAuth` (contact). Every route that a contact can
//! legitimately reach gates the sensitive branch on
//! [`CallerContext::require_capability`], which DB-loads the effective
//! capability set from `portal_roles` per request so a role revoke lands on
//! the very next call, not after the JWT TTL. `caps` on the JWT stays for UI
//! hydration only and is deliberately never consulted here.
//!
//! Prompt 008 SESSION SCOPE: this ships the extractor + primary
//! contact-plane endpoints (tickets create/list/get + notes-create,
//! invoices list/get, quotes list/get/accept/decline, and the
//! Companies/Contacts staff-only lockout). The following surfaces are
//! deferred to the follow-up sweep tracked in the prompt-008 report:
//!
//! - Contracts, Assets, Projects, Time-entries, Knowledge Base, Forms,
//!   Approvals, Notifications endpoints.
//! - `PUT /api/v1/users/me` staff-only guard,
//!   `PUT /api/v1/contact/auth/me` contact-profile edit.
//! - Sub-user invite flow (`POST /api/v1/contact/company/contacts`) and
//!   sub-user manage endpoints.
//! - RLS `company_id` GUC + row-level company scope filter.
//! - Ticket reopen (as a discrete endpoint) + invoice PDF / checkout
//!   contact-facing routes (they do not exist yet).

use axum::extract::FromRequestParts;
use uuid::Uuid;

use super::middleware::RequireAuthState;
use crate::db::Database;
use crate::modules::auth::{AuthState, TenantId};
use crate::modules::contact_portal::middleware::ContactAuthState;
use crate::modules::contact_portal::models::ContactSession;
use crate::utils::error::{AppError, AppResult};

/// mokosh-contact-login prompt 008: the two planes a dual-plane handler
/// may see, wrapped in one enum. Staff callers land in [`Self::Staff`]
/// with the full [`AuthState`] (so the handler can still read role, tenant,
/// membership set); contact callers land in [`Self::Contact`] with the
/// [`ContactSession`] the contact-portal middleware attached.
///
/// A handler that only wants to service one plane rejects the other with
/// [`Self::require_staff`] (contacts get 403) or by branching on the
/// variant directly.
// Merge cleanup: box the large variant in a follow-up (out of scope for the route-overlap fix)
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum CallerContext {
    /// Staff bearer: the full auth state populated by
    /// `auth_middleware` (identity, active membership, memberships).
    Staff(AuthState),
    /// Contact bearer: the session row populated by
    /// `portal_contact_middleware`.
    Contact(ContactSession),
}

impl CallerContext {
    /// Tenant the caller is scoped to. Every service call downstream of
    /// this is tenant-scoped, so surface it as a typed [`TenantId`] the
    /// handler can pass straight through.
    pub fn tenant(&self) -> TenantId {
        match self {
            Self::Staff(state) => {
                let raw = state.tenant_id.unwrap_or_else(Uuid::nil);
                TenantId::from_trusted(raw)
            }
            Self::Contact(session) => TenantId::from_trusted(session.tenant_id),
        }
    }

    /// Today where the CALLER is (PMS-1027): a staff user's `users.timezone`,
    /// a contact's `contacts.timezone`, `UTC` when neither is set. A quote
    /// valid through today has to be accepted on today where the customer
    /// is, not on today in UTC, which from 14:00 Pacific onward is tomorrow.
    /// The contact arm reads one column on its own tenant-GUC connection;
    /// `ContactSession` is minted at login and does not carry the zone.
    pub async fn today(&self, db: &Database) -> AppResult<chrono::NaiveDate> {
        let now = chrono::Utc::now();
        let zone = match self {
            Self::Staff(state) => state
                .user
                .as_ref()
                .map(|u| u.timezone.clone())
                .unwrap_or_else(|| "UTC".to_string()),
            Self::Contact(session) => {
                let mut tx = db.begin_with_tenant(self.tenant()).await?;
                sqlx::query_scalar::<_, Option<String>>(
                    "SELECT timezone FROM contacts WHERE id = $1 AND tenant_id = $2",
                )
                .bind(session.id)
                .bind(session.tenant_id)
                .fetch_optional(&mut *tx)
                .await?
                .flatten()
                .unwrap_or_else(|| "UTC".to_string())
            }
        };
        Ok(mokosh_types::datetime::user_today(now, &zone))
    }

    /// Raw tenant `Uuid` for callers that still take a bare `Uuid`.
    pub fn tenant_id(&self) -> Uuid {
        self.tenant().get()
    }

    /// The company scope, if the caller is bound to one. Contacts are
    /// scoped to a single `company_id`; staff are unbounded and return
    /// `None`.
    pub fn company_scope(&self) -> Option<Uuid> {
        match self {
            Self::Staff(_) => None,
            Self::Contact(session) => Some(session.company_id),
        }
    }

    /// The contact id when the caller is on the contact plane; `None`
    /// for staff. Used by handlers that stamp `created_by_contact_id`.
    pub fn contact_id(&self) -> Option<Uuid> {
        match self {
            Self::Staff(_) => None,
            Self::Contact(session) => Some(session.id),
        }
    }

    /// `true` when the caller is a contact bearer.
    pub fn is_contact(&self) -> bool {
        matches!(self, Self::Contact(_))
    }

    /// Reject a contact caller with 403 so a handler that must only run
    /// as staff (create/void/send invoice, create/send/revise quote,
    /// every Companies + Contacts CRM route) stays closed to the
    /// contact plane. Staff callers pass through.
    pub fn require_staff(&self) -> AppResult<()> {
        match self {
            Self::Staff(_) => Ok(()),
            Self::Contact(_) => Err(AppError::Forbidden(
                "This endpoint is restricted to staff users.".to_string(),
            )),
        }
    }

    /// mokosh-contact-login prompt 008: gate a mutation on the effective
    /// capability set, loaded from `portal_roles` FOR THIS REQUEST.
    ///
    /// - Staff caller: no-op success. Staff bypass the portal_roles
    ///   capability lattice - the caller's staff role gate + module gate
    ///   are the staff-plane authorization surface.
    /// - Contact caller: DB-loads the union of `portal_roles.capabilities`
    ///   over every row of `contact_role_assignments` for this contact,
    ///   and 403s when the requested capability is absent. The JWT
    ///   `caps` claim is deliberately NOT consulted so a role revoke via
    ///   `PUT /api/v1/contacts/{id}/portal-roles` lands on the next
    ///   request, not after the 15-min access-token TTL.
    pub async fn require_capability(&self, cap: &str, db: &Database) -> AppResult<()> {
        let session = match self {
            Self::Staff(_) => return Ok(()),
            Self::Contact(session) => session,
        };
        let caps = load_contact_capabilities(db, session.tenant_id, session.id).await?;
        if caps.iter().any(|c| c == cap) {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "Missing required capability: {cap}"
            )))
        }
    }
}

/// mokosh-contact-login prompt 008: reload the effective capability set
/// for a portal contact from `portal_roles`. Kept out of the enum's
/// method body so it can also back
/// `PortalRoleService::load_contact_capabilities` (same query, same
/// posture) without dragging the enum into the service layer.
///
/// Uses the migrator pool because `contact_role_assignments` +
/// `portal_roles` are RLS-covered and the belt-and-braces `WHERE
/// tenant_id = $1` keeps the query safe even if the GUC drifts.
pub async fn load_contact_capabilities(
    db: &Database,
    tenant_id: Uuid,
    contact_id: Uuid,
) -> AppResult<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT cap
        FROM contact_role_assignments cra
        INNER JOIN portal_roles pr ON pr.id = cra.role_id,
        LATERAL unnest(pr.capabilities) AS cap
        WHERE cra.contact_id = $1 AND cra.tenant_id = $2
        ORDER BY cap
        "#,
    )
    .bind(contact_id)
    .bind(tenant_id)
    .fetch_all(db.migrator_pool())
    .await?;
    Ok(rows.into_iter().map(|(c,)| c).collect())
}

/// mokosh-contact-login prompt 008: extractor for a dual-plane handler.
///
/// Resolution order: try `AuthState` first (staff bearer decoded by
/// `auth_middleware`); if the extension is present and authenticated,
/// return `Staff(state)`. Otherwise fall back to `ContactAuthState`
/// (contact bearer decoded by `portal_contact_middleware`); if present
/// and authenticated, return `Contact(session)`. Neither = 401.
///
/// A tombstoned staff row still surfaces as 410 Gone (`ACCOUNT_DELETED`)
/// via `RequireAuthState` on the staff branch, matching the existing
/// staff-plane extractor contract.
#[derive(Clone, Debug)]
pub struct RequireCallerContext(pub CallerContext);

impl<S> FromRequestParts<S> for RequireCallerContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Try the staff plane first. `RequireAuthState` shares the
        // deleted-account short-circuit with `RequireAuth`, so a
        // tombstoned bearer maps to 410 Gone before we consider the
        // contact fallback. A plain "no staff auth" comes back as 401
        // which we swallow into the fallback path.
        let staff_state = parts.extensions.get::<AuthState>().cloned();
        if let Some(state) = staff_state {
            if state.is_authenticated {
                let full = RequireAuthState::from_request_parts(parts, &()).await?;
                return Ok(RequireCallerContext(CallerContext::Staff(full.0)));
            }
            if state.deleted {
                return Err(AppError::AccountDeleted);
            }
        }
        // Fall back to the contact plane.
        let contact_state = parts.extensions.get::<ContactAuthState>().cloned();
        if let Some(state) = contact_state {
            if let Some(session) = state.session {
                return Ok(RequireCallerContext(CallerContext::Contact(session)));
            }
        }
        let _ = state; // FromRequestParts signature symmetry
        Err(AppError::Unauthorized)
    }
}
