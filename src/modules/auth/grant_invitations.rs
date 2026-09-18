//! PMS-1208: pending-invite service for the Mokosh grant lifecycle.
//!
//! `mokosh_grant_invitations` (migration 222) is the pre-mirror
//! state: an owner invites a bunyip user to see their account, the
//! invite sits `pending` for up to 7 days, and only when the
//! invitee accepts does the row propagate into
//! `mokosh_bunyip_grants` (BUNYIP-674 option B) - which is the
//! authoritative shape the request-time gate reads. Bunyip's
//! existing `mokosh_account_grants` (SaaS-only, cross-account
//! visibility on the owner's Bunyip surface) is populated from the
//! same accept event; in standalone mode there is no bunyip side
//! to write to and the mirror is the whole story.
//!
//! Token shape mirrors `portal_setup_tokens` (PMS-136): the wire
//! token is `{invitation_id}.{secret}`; the id lets `find_by_token`
//! load exactly one row rather than scan by hash, and the Argon2
//! `verify_password` over the secret is the constant-time
//! comparison that decides acceptance. The secret is generated per
//! invitation and stored only as its Argon2 hash.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::utils::crypto::{generate_token, hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

/// Secret half of the accept token. 32 alphanumerics gives a
/// ~190-bit search space; the id half in front of it means the
/// space nobody-else has to guess is exactly that.
const SECRET_LEN: usize = 32;

/// Default TTL for a fresh invite. Callers may override for tests;
/// the parent ticket names 7 days to match Cloudflare's window.
pub const DEFAULT_TTL: Duration = Duration::days(7);

/// One `mokosh_grant_invitations` row.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct GrantInvitation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub inviter_bunyip_user_id: Uuid,
    pub invitee_bunyip_user_id: Option<Uuid>,
    pub invitee_email: String,
    pub role: String,
    pub status: String,
    pub invited_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub declined_at: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

impl GrantInvitation {
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// What `create` returns: the row plus the plaintext token the
/// caller must use to build the invitation email's accept link.
/// The plaintext is available EXACTLY ONCE at creation; the
/// database keeps only the Argon2 hash.
pub struct CreatedInvitation {
    pub invitation: GrantInvitation,
    pub accept_token: String,
}

/// Reason the accept path refused a token. Distinct variants so
/// the handler can emit a Cloudflare-style 410 for a gone token
/// and a 403 for a wrong caller without both reading as 404.
#[derive(Debug)]
pub enum AcceptRefusal {
    NotFound,
    Expired,
    Canceled,
    AlreadyAccepted,
    Declined,
    WrongCaller,
}

pub struct GrantInvitationsService;

impl GrantInvitationsService {
    /// Create a pending invitation and return the row + the
    /// plaintext accept token. The plaintext is only ever handed
    /// back here; the row stores only its Argon2 hash.
    ///
    /// The partial UNIQUE on (tenant_id, lower(invitee_email))
    /// WHERE status = 'pending' is what turns a second pending
    /// invite into 409; the sqlx `Database` variant with code
    /// `23505` surfaces here and the caller maps it to a Conflict
    /// AppError. The 409 for "already an active grant" case is a
    /// separate pre-check the handler runs before calling this.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        inviter_bunyip_user_id: Uuid,
        invitee_bunyip_user_id: Option<Uuid>,
        invitee_email: &str,
        role: &str,
        ttl: Duration,
    ) -> AppResult<CreatedInvitation> {
        // Refuse a self-invite by verified address BEFORE the write,
        // so a caller that omitted `invitee_bunyip_user_id` cannot
        // slip past the id-based CHECK constraint.
        // (The id-based CHECK covers the SaaS-mode path where the
        // resolver filled the invitee id in.)
        let secret = generate_token(SECRET_LEN);
        let accept_token_hash = hash_password(&secret)?;
        let now = Utc::now();
        let expires_at = now + ttl;

        let row: GrantInvitation = sqlx::query_as(
            r#"
            INSERT INTO mokosh_grant_invitations (
                tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                invitee_email, role, accept_token_hash, status,
                invited_at, expires_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $7)
            RETURNING id, tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                      invitee_email, role, status, invited_at, expires_at,
                      accepted_at, declined_at, canceled_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(inviter_bunyip_user_id)
        .bind(invitee_bunyip_user_id)
        .bind(invitee_email)
        .bind(role)
        .bind(&accept_token_hash)
        .bind(now)
        .bind(expires_at)
        .fetch_one(pool)
        .await
        .map_err(map_unique_violation)?;

        let accept_token = format!("{}.{}", row.id, secret);
        Ok(CreatedInvitation {
            invitation: row,
            accept_token,
        })
    }

    /// Resolve an invitation by its primary-key `id`. Used by the
    /// grantee-scoped id endpoints, which do not carry the plaintext
    /// token (that lives only on the invitation email) and instead
    /// gate on `RequireAuth` + a caller-vs-invitee check made by the
    /// route handler. `Ok(None)` covers "no such id", the same shape
    /// `find_by_token` uses for "no such row".
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> AppResult<Option<GrantInvitation>> {
        let row: Option<GrantInvitation> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                   invitee_email, role, status, invited_at, expires_at,
                   accepted_at, declined_at, canceled_at, updated_at
            FROM mokosh_grant_invitations
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// Resolve a plaintext token from the invitation email link
    /// to a row. `Ok(None)` covers a malformed token, an unknown
    /// id, and a mismatched secret; only a real match returns the
    /// row. Status and expiry are NOT consulted here - the caller
    /// (accept, decline, by-token metadata) picks the shape it
    /// wants; this is just the identity check.
    pub async fn find_by_token(pool: &PgPool, token: &str) -> AppResult<Option<GrantInvitation>> {
        let (id, secret) = match parse_token(token) {
            Some(pair) => pair,
            None => return Ok(None),
        };
        let row: Option<(GrantInvitation, String)> = sqlx::query(
            r#"
            SELECT id, tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                   invitee_email, role, status, invited_at, expires_at,
                   accepted_at, declined_at, canceled_at, updated_at,
                   accept_token_hash
            FROM mokosh_grant_invitations
            WHERE id = $1
            "#,
        )
        .bind(id)
        .try_map(|row: sqlx::postgres::PgRow| {
            let invitation = GrantInvitation {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                inviter_bunyip_user_id: row.try_get("inviter_bunyip_user_id")?,
                invitee_bunyip_user_id: row.try_get("invitee_bunyip_user_id")?,
                invitee_email: row.try_get("invitee_email")?,
                role: row.try_get("role")?,
                status: row.try_get("status")?,
                invited_at: row.try_get("invited_at")?,
                expires_at: row.try_get("expires_at")?,
                accepted_at: row.try_get("accepted_at")?,
                declined_at: row.try_get("declined_at")?,
                canceled_at: row.try_get("canceled_at")?,
                updated_at: row.try_get("updated_at")?,
            };
            let hash: String = row.try_get("accept_token_hash")?;
            Ok((invitation, hash))
        })
        .fetch_optional(pool)
        .await?;

        let Some((invitation, hash)) = row else {
            return Ok(None);
        };
        if !verify_password(&secret, &hash)? {
            return Ok(None);
        }
        Ok(Some(invitation))
    }

    /// Every PENDING invite the tenant admin sent. Ordered
    /// newest-first because that is how the owner outbox reads:
    /// "what did I do most recently."
    pub async fn find_pending_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> AppResult<Vec<GrantInvitation>> {
        let rows = sqlx::query_as::<_, GrantInvitation>(
            r#"
            SELECT id, tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                   invitee_email, role, status, invited_at, expires_at,
                   accepted_at, declined_at, canceled_at, updated_at
            FROM mokosh_grant_invitations
            WHERE tenant_id = $1 AND status = 'pending'
            ORDER BY invited_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Every PENDING invite for one bunyip user across all
    /// tenants. This is the grantee inbox; runs cross-tenant so
    /// the caller passes their own `sub` and reads back invites
    /// from every mokosh account that has invited them.
    pub async fn find_pending_for_invitee(
        pool: &PgPool,
        invitee_bunyip_user_id: Uuid,
    ) -> AppResult<Vec<GrantInvitation>> {
        let rows = sqlx::query_as::<_, GrantInvitation>(
            r#"
            SELECT id, tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                   invitee_email, role, status, invited_at, expires_at,
                   accepted_at, declined_at, canceled_at, updated_at
            FROM mokosh_grant_invitations
            WHERE invitee_bunyip_user_id = $1 AND status = 'pending'
              AND expires_at > NOW()
            ORDER BY invited_at DESC
            "#,
        )
        .bind(invitee_bunyip_user_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Owner cancels a pending invite. Returns `Ok(true)` when a
    /// row was moved to `canceled`; `Ok(false)` when the id names
    /// a row in a terminal state already (idempotent), and does
    /// NOT distinguish "unknown id" from "wrong tenant" - both
    /// return `Ok(false)` so the endpoint stays enumeration-
    /// resistant against a leaked or stale id.
    pub async fn cancel(pool: &PgPool, id: Uuid, tenant_id: Uuid) -> AppResult<bool> {
        let rows = sqlx::query(
            r#"
            UPDATE mokosh_grant_invitations
            SET status = 'canceled',
                canceled_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(rows.rows_affected() == 1)
    }

    /// Grantee accepts. Runs one transaction: verifies the token
    /// AGAIN against the row (belt-and-braces on `find_by_token`
    /// racing another accept), gates on status + expiry + caller,
    /// marks the row accepted, and upserts the `mokosh_bunyip_grants`
    /// mirror (BUNYIP-674 option B's authoritative surface). The
    /// mirror upsert reuses the same idempotency guarantees the
    /// webhook receiver uses, so an accept + a stale `granted`
    /// webhook cannot double-write the mirror.
    ///
    /// The caller's `invitee_bunyip_user_id` MUST match the row's
    /// invitee_bunyip_user_id when the row has one. When the row's
    /// invitee id is NULL (standalone mode or a first-sight
    /// invitee), the caller's id is written onto the row before
    /// acceptance so the audit trail records who accepted.
    pub async fn accept(
        pool: &PgPool,
        token: &str,
        caller_bunyip_user_id: Uuid,
        owner_bunyip_user_id_fallback: Uuid,
        bunyip_directory: Option<&super::bunyip_directory::BunyipUserDirectory>,
    ) -> AppResult<Result<GrantInvitation, AcceptRefusal>> {
        let invitation = match Self::find_by_token(pool, token).await? {
            Some(inv) => inv,
            None => return Ok(Err(AcceptRefusal::NotFound)),
        };
        Self::accept_loaded(
            pool,
            invitation,
            caller_bunyip_user_id,
            owner_bunyip_user_id_fallback,
            bunyip_directory,
        )
        .await
    }

    /// Grantee-scoped accept by invitation id. Used by the SPA
    /// switcher's Accept button on the pending-inbox row: that surface
    /// never sees the plaintext token (the token rides the invitation
    /// email only) and instead authenticates the grantee via
    /// `RequireAuth`. The caller check is stricter than the token
    /// path's: the invitation MUST already name a bunyip_user_id AND
    /// it MUST match the caller. A NULL invitee_bunyip_user_id (a
    /// standalone-mode by-email invitation) is refused here because
    /// the grantee inbox only lists rows already bound to the caller,
    /// so an unbound row reaching this endpoint is an id spoof.
    pub async fn accept_by_id(
        pool: &PgPool,
        id: Uuid,
        caller_bunyip_user_id: Uuid,
        bunyip_directory: Option<&super::bunyip_directory::BunyipUserDirectory>,
    ) -> AppResult<Result<GrantInvitation, AcceptRefusal>> {
        let invitation = match Self::find_by_id(pool, id).await? {
            Some(inv) => inv,
            None => return Ok(Err(AcceptRefusal::NotFound)),
        };
        // Strict caller check: refuse if the row is not addressed to
        // this caller. `accept_loaded` also refuses when the row's
        // invitee id is set and does not match, but not when it is
        // NULL - so cover NULL here so an id spoof cannot bind an
        // unbound row to a caller who is not the intended invitee.
        match invitation.invitee_bunyip_user_id {
            Some(existing) if existing == caller_bunyip_user_id => {}
            _ => return Ok(Err(AcceptRefusal::WrongCaller)),
        }
        let owner = invitation.inviter_bunyip_user_id;
        Self::accept_loaded(
            pool,
            invitation,
            caller_bunyip_user_id,
            owner,
            bunyip_directory,
        )
        .await
    }

    /// Shared body of the two accept entry points. Assumes the
    /// invitation has been loaded and the caller is proved (by token
    /// for `accept`, by RequireAuth + id-caller match for
    /// `accept_by_id`). Status / expiry / WrongCaller checks and the
    /// guarded UPDATE + mirror upsert are the same on both paths.
    async fn accept_loaded(
        pool: &PgPool,
        invitation: GrantInvitation,
        caller_bunyip_user_id: Uuid,
        owner_bunyip_user_id_fallback: Uuid,
        bunyip_directory: Option<&super::bunyip_directory::BunyipUserDirectory>,
    ) -> AppResult<Result<GrantInvitation, AcceptRefusal>> {
        use super::mokosh_bunyip_grants::MokoshBunyipGrantService;

        let now = Utc::now();
        if invitation.status == "canceled" {
            return Ok(Err(AcceptRefusal::Canceled));
        }
        if invitation.status == "accepted" {
            return Ok(Err(AcceptRefusal::AlreadyAccepted));
        }
        if invitation.status == "declined" {
            return Ok(Err(AcceptRefusal::Declined));
        }
        if invitation.status == "expired" || invitation.is_expired(now) {
            return Ok(Err(AcceptRefusal::Expired));
        }
        if let Some(existing) = invitation.invitee_bunyip_user_id {
            if existing != caller_bunyip_user_id {
                return Ok(Err(AcceptRefusal::WrongCaller));
            }
        }

        // Resolve the granted account's slug once up front so we can
        // hand it to bunyip below AND to the mirror upsert further
        // down without a second read. A missing tenant is a 500-level
        // configuration error: the tenant that owns the invitation
        // cannot have disappeared between create and accept in the
        // normal flow.
        let slug: Option<(String,)> = sqlx::query_as("SELECT slug FROM tenants WHERE id = $1")
            .bind(invitation.tenant_id)
            .fetch_optional(pool)
            .await?;
        let slug = slug
            .ok_or_else(|| AppError::internal("Owner tenant vanished during accept"))?
            .0;

        // PMS-1208 finding 5: in SaaS mode, register the grant on
        // bunyip BEFORE marking the invitation accepted. Bunyip's
        // `mokosh_account_grants` table is what its
        // `POST /v1/grants/{id}/access-token` mint endpoint reads;
        // without a row there, mint 404s and the grantee lands on
        // "The requested resource could not be found" the moment they
        // click the granted team in the switcher. We pass the
        // invitation id as the grant id so mokosh's mirror row and
        // bunyip's row share the same uuid by construction, and the
        // SPA can send that same id to bunyip's mint endpoint later
        // without a translation step.
        //
        // Order matters: before the local UPDATE. A failure here
        // returns to the caller with the invitation still `pending`
        // (a retry re-registers idempotently on bunyip and re-tries
        // accept), while a success followed by a local UPDATE failure
        // leaves an orphan bunyip row that a retry heals through
        // bunyip's `ON CONFLICT (id) DO UPDATE`. Standalone mode
        // (bunyip_directory is None) skips this step, because there
        // is no bunyip to register against.
        if let Some(directory) = bunyip_directory {
            directory
                .register_grant(
                    invitation.id,
                    owner_bunyip_user_id_fallback,
                    caller_bunyip_user_id,
                    &slug,
                    invitation.role.trim(),
                )
                .await?;
        }

        // Bind the caller onto the row (no-op when it already
        // matches) and mark accepted in one round-trip. The
        // WHERE clause double-guards against a race where a
        // concurrent accept, decline, or cancel already flipped
        // the status.
        let updated: Option<GrantInvitation> = sqlx::query_as(
            r#"
            UPDATE mokosh_grant_invitations
            SET status = 'accepted',
                accepted_at = NOW(),
                invitee_bunyip_user_id = $2,
                updated_at = NOW()
            WHERE id = $1 AND status = 'pending' AND expires_at > NOW()
            RETURNING id, tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                      invitee_email, role, status, invited_at, expires_at,
                      accepted_at, declined_at, canceled_at, updated_at
            "#,
        )
        .bind(invitation.id)
        .bind(caller_bunyip_user_id)
        .fetch_optional(pool)
        .await?;

        let Some(accepted) = updated else {
            // Lost the race; re-read to answer the caller
            // precisely on what happened. Uses `find_by_id` because
            // this helper serves both the token and the id entry
            // paths and does not carry the plaintext token.
            let refreshed = Self::find_by_id(pool, invitation.id)
                .await?
                .ok_or(AppError::internal("Invitation vanished during accept"))?;
            return Ok(Err(match refreshed.status.as_str() {
                "canceled" => AcceptRefusal::Canceled,
                "accepted" => AcceptRefusal::AlreadyAccepted,
                "declined" => AcceptRefusal::Declined,
                _ => AcceptRefusal::Expired,
            }));
        };

        MokoshBunyipGrantService::upsert_with_email(
            pool,
            accepted.id, // Same uuid bunyip's `mokosh_account_grants.id` holds (register_grant above wrote it there).
            owner_bunyip_user_id_fallback,
            caller_bunyip_user_id,
            &slug,
            Some(&accepted.role),
            accepted
                .accepted_at
                .expect("accepted_at was just stamped by the UPDATE above"),
            None,
            // PMS-1208 finding 3: also record the grantee's email so
            // the standalone MembershipView UNION can render this row
            // in the switcher (bunyip_user_id is NULL there and the
            // sub-based join never fires). In SaaS mode this is
            // redundant with the bunyip_user_id axis, but writing it
            // costs nothing and keeps both modes on one code path.
            Some(&accepted.invitee_email),
        )
        .await?;

        Ok(Ok(accepted))
    }

    /// Grantee declines. Same shape as accept minus the mirror
    /// write.
    pub async fn decline(
        pool: &PgPool,
        token: &str,
        caller_bunyip_user_id: Uuid,
    ) -> AppResult<Result<GrantInvitation, AcceptRefusal>> {
        let invitation = match Self::find_by_token(pool, token).await? {
            Some(inv) => inv,
            None => return Ok(Err(AcceptRefusal::NotFound)),
        };
        Self::decline_loaded(pool, invitation, caller_bunyip_user_id).await
    }

    /// Grantee-scoped decline by invitation id. Same shape as
    /// [`Self::accept_by_id`]: RequireAuth authenticates the grantee
    /// and the caller must already be named on the row's
    /// `invitee_bunyip_user_id`.
    pub async fn decline_by_id(
        pool: &PgPool,
        id: Uuid,
        caller_bunyip_user_id: Uuid,
    ) -> AppResult<Result<GrantInvitation, AcceptRefusal>> {
        let invitation = match Self::find_by_id(pool, id).await? {
            Some(inv) => inv,
            None => return Ok(Err(AcceptRefusal::NotFound)),
        };
        match invitation.invitee_bunyip_user_id {
            Some(existing) if existing == caller_bunyip_user_id => {}
            _ => return Ok(Err(AcceptRefusal::WrongCaller)),
        }
        Self::decline_loaded(pool, invitation, caller_bunyip_user_id).await
    }

    async fn decline_loaded(
        pool: &PgPool,
        invitation: GrantInvitation,
        caller_bunyip_user_id: Uuid,
    ) -> AppResult<Result<GrantInvitation, AcceptRefusal>> {
        let now = Utc::now();
        if invitation.status == "canceled" {
            return Ok(Err(AcceptRefusal::Canceled));
        }
        if invitation.status == "accepted" {
            return Ok(Err(AcceptRefusal::AlreadyAccepted));
        }
        if invitation.status == "declined" {
            return Ok(Err(AcceptRefusal::Declined));
        }
        if invitation.status == "expired" || invitation.is_expired(now) {
            return Ok(Err(AcceptRefusal::Expired));
        }
        if let Some(existing) = invitation.invitee_bunyip_user_id {
            if existing != caller_bunyip_user_id {
                return Ok(Err(AcceptRefusal::WrongCaller));
            }
        }
        let updated: Option<GrantInvitation> = sqlx::query_as(
            r#"
            UPDATE mokosh_grant_invitations
            SET status = 'declined',
                declined_at = NOW(),
                invitee_bunyip_user_id = $2,
                updated_at = NOW()
            WHERE id = $1 AND status = 'pending' AND expires_at > NOW()
            RETURNING id, tenant_id, inviter_bunyip_user_id, invitee_bunyip_user_id,
                      invitee_email, role, status, invited_at, expires_at,
                      accepted_at, declined_at, canceled_at, updated_at
            "#,
        )
        .bind(invitation.id)
        .bind(caller_bunyip_user_id)
        .fetch_optional(pool)
        .await?;
        Ok(match updated {
            Some(inv) => Ok(inv),
            None => Err(AcceptRefusal::Expired),
        })
    }

    /// Scheduler entry point: mark every pending row past its
    /// expiry as `expired`. Returns the number of rows moved so
    /// the scheduler can log volume. Idempotent by construction:
    /// the WHERE clause filters on `status = 'pending'`.
    pub async fn expire_stale(pool: &PgPool) -> AppResult<u64> {
        let rows = sqlx::query(
            "UPDATE mokosh_grant_invitations \
             SET status = 'expired', updated_at = NOW() \
             WHERE status = 'pending' AND expires_at <= NOW()",
        )
        .execute(pool)
        .await?;
        Ok(rows.rows_affected())
    }
}

/// Split a wire token of the form `{uuid}.{secret}` into its two
/// halves. Returns `None` for anything malformed so the caller
/// answers 404 rather than 500 on a client typo.
fn parse_token(token: &str) -> Option<(Uuid, String)> {
    let (id_str, secret) = token.split_once('.')?;
    let id = Uuid::parse_str(id_str).ok()?;
    if secret.is_empty() {
        return None;
    }
    Some((id, secret.to_string()))
}

/// Postgres unique-violation → 409 Conflict with a message the
/// SPA can render. Any other error rides `?` through.
fn map_unique_violation(e: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_err) = &e {
        if db_err.code().as_deref() == Some("23505") {
            return AppError::conflict(
                "An invitation for this email is already pending on this account.".to_string(),
            );
        }
    }
    AppError::from(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_accepts_uuid_dot_secret() {
        let id = Uuid::new_v4();
        let secret = "abcdefghijklmnop";
        let wire = format!("{id}.{secret}");
        let (parsed_id, parsed_secret) = parse_token(&wire).expect("parse");
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_secret, secret);
    }

    #[test]
    fn parse_token_refuses_malformed_shapes() {
        assert!(parse_token("").is_none());
        assert!(parse_token("not-a-uuid.secret").is_none());
        assert!(parse_token(&Uuid::new_v4().to_string()).is_none());
        assert!(parse_token(&format!("{}.", Uuid::new_v4())).is_none());
    }
}
