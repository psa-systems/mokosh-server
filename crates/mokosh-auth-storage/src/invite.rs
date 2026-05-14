//! Postgres-backed `InviteRepository`. The accept transaction is the
//! security-critical piece: SERIALIZABLE isolation with retry-on-40001
//! so two concurrent acceptances of the same token can never both
//! create a user.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mokosh_auth_core::{
    AuthError, Invite, InviteRepository, NewInvite, TenantId, User, UserId, UserRole, UserStatus,
};
use uuid::Uuid;

use crate::conv::{db_err, UserRow};
use crate::pool::AuthPool;

pub struct PgInviteRepository {
    pool: AuthPool,
}

impl PgInviteRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct InviteRow {
    id: Uuid,
    tenant_id: Uuid,
    email: String,
    role: String,
    invited_by: Uuid,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    used_by: Option<Uuid>,
    revoked_at: Option<DateTime<Utc>>,
    revoked_by: Option<Uuid>,
    revoke_reason: Option<String>,
    note: Option<String>,
}

impl TryFrom<InviteRow> for Invite {
    type Error = AuthError;
    fn try_from(r: InviteRow) -> Result<Self, Self::Error> {
        Ok(Invite {
            id: r.id,
            tenant_id: TenantId(r.tenant_id),
            email: r.email,
            role: UserRole::parse(&r.role)
                .ok_or_else(|| AuthError::Storage(format!("invalid invite role: {}", r.role)))?,
            invited_by: UserId(r.invited_by),
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            used_at: r.used_at,
            used_by: r.used_by.map(UserId),
            revoked_at: r.revoked_at,
            revoked_by: r.revoked_by.map(UserId),
            revoke_reason: r.revoke_reason,
            note: r.note,
        })
    }
}

const SELECT_INVITE: &str = r#"
    SELECT id, tenant_id, email, role, invited_by, issued_at, expires_at,
           used_at, used_by, revoked_at, revoked_by, revoke_reason, note
    FROM mokosh_auth.admin_invites
"#;

#[async_trait]
impl InviteRepository for PgInviteRepository {
    async fn issue(&self, new: NewInvite) -> Result<Invite, AuthError> {
        let token_hash = mokosh_auth_crypto::hash_opaque_token(&new.token);
        let row: InviteRow = sqlx::query_as(&format!(
            "INSERT INTO mokosh_auth.admin_invites
                (tenant_id, email, role, token_hash, invited_by, expires_at, note)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, tenant_id, email, role, invited_by, issued_at, expires_at,
                       used_at, used_by, revoked_at, revoked_by, revoke_reason, note",
        ))
        .bind(new.tenant_id.0)
        .bind(&new.email)
        .bind(new.role.as_str())
        .bind(&token_hash[..])
        .bind(new.invited_by.0)
        .bind(new.expires_at)
        .bind(&new.note)
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("an open invite already exists for this email".into())
            }
            _ => db_err(e),
        })?;
        Invite::try_from(row)
    }

    async fn find_open_by_token(&self, token: &str) -> Result<Option<Invite>, AuthError> {
        let token_hash = mokosh_auth_crypto::hash_opaque_token(token);
        let now = Utc::now();
        let row: Option<InviteRow> = sqlx::query_as(&format!(
            "{SELECT_INVITE}
             WHERE token_hash = $1
               AND used_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > $2"
        ))
        .bind(&token_hash[..])
        .bind(now)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(Invite::try_from).transpose()
    }

    async fn find_by_id(
        &self,
        invite_id: Uuid,
        tenant_id: TenantId,
    ) -> Result<Option<Invite>, AuthError> {
        let row: Option<InviteRow> =
            sqlx::query_as(&format!("{SELECT_INVITE} WHERE id = $1 AND tenant_id = $2"))
                .bind(invite_id)
                .bind(tenant_id.0)
                .fetch_optional(self.pool.pg())
                .await
                .map_err(db_err)?;
        row.map(Invite::try_from).transpose()
    }

    async fn find_open_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<Invite>, AuthError> {
        let row: Option<InviteRow> = sqlx::query_as(&format!(
            "{SELECT_INVITE}
             WHERE tenant_id = $1 AND email = $2
               AND used_at IS NULL AND revoked_at IS NULL"
        ))
        .bind(tenant_id.0)
        .bind(email)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(Invite::try_from).transpose()
    }

    async fn list_open(&self, tenant_id: TenantId) -> Result<Vec<Invite>, AuthError> {
        let rows: Vec<InviteRow> = sqlx::query_as(&format!(
            "{SELECT_INVITE}
             WHERE tenant_id = $1 AND used_at IS NULL AND revoked_at IS NULL
             ORDER BY issued_at DESC"
        ))
        .bind(tenant_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(Invite::try_from).collect()
    }

    async fn revoke(
        &self,
        invite_id: Uuid,
        tenant_id: TenantId,
        revoked_by: UserId,
        reason: &str,
    ) -> Result<(), AuthError> {
        // Idempotent: a no-op match for already-terminal rows still
        // returns Ok. The WHERE clause filters out used/revoked rows
        // so the UPDATE doesn't accidentally re-stamp them.
        sqlx::query(
            "UPDATE mokosh_auth.admin_invites
             SET revoked_at = NOW(), revoked_by = $1, revoke_reason = $2
             WHERE id = $3 AND tenant_id = $4
               AND used_at IS NULL AND revoked_at IS NULL",
        )
        .bind(revoked_by.0)
        .bind(reason)
        .bind(invite_id)
        .bind(tenant_id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn replace_token(
        &self,
        invite_id: Uuid,
        tenant_id: TenantId,
        ttl_days: i64,
    ) -> Result<(Invite, String), AuthError> {
        let raw_token = mokosh_auth_crypto::generate_opaque_token();
        let new_hash = mokosh_auth_crypto::hash_opaque_token(&raw_token);
        let new_expiry = Utc::now() + Duration::days(ttl_days);

        let row: InviteRow = sqlx::query_as(
            "UPDATE mokosh_auth.admin_invites
             SET token_hash = $1, expires_at = $2
             WHERE id = $3 AND tenant_id = $4
               AND used_at IS NULL AND revoked_at IS NULL
             RETURNING id, tenant_id, email, role, invited_by, issued_at, expires_at,
                       used_at, used_by, revoked_at, revoked_by, revoke_reason, note",
        )
        .bind(&new_hash[..])
        .bind(new_expiry)
        .bind(invite_id)
        .bind(tenant_id.0)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?
        .ok_or_else(|| AuthError::NotFound)?;
        Ok((Invite::try_from(row)?, raw_token))
    }

    async fn accept(
        &self,
        token: &str,
        password_hash: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<User, AuthError> {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self
                .accept_once(token, password_hash, first_name, last_name)
                .await
            {
                Err(AuthError::Storage(msg))
                    if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS =>
                {
                    tracing::debug!(attempt, "invite accept serialization conflict; retrying");
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }

    async fn accept_existing(&self, token: &str, user_id: UserId) -> Result<User, AuthError> {
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self.accept_existing_once(token, user_id).await {
                Err(AuthError::Storage(msg))
                    if msg.contains("40001") && attempt + 1 < MAX_ATTEMPTS =>
                {
                    tracing::debug!(
                        attempt,
                        "invite membership-accept serialization conflict; retrying"
                    );
                    continue;
                }
                other => return other,
            }
        }
        unreachable!("loop returns or continues at most MAX_ATTEMPTS times")
    }
}

impl PgInviteRepository {
    async fn accept_once(
        &self,
        token: &str,
        password_hash: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<User, AuthError> {
        let token_hash = mokosh_auth_crypto::hash_opaque_token(token);
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        // 1. Lock the invite row.
        #[derive(sqlx::FromRow)]
        struct Locked {
            id: Uuid,
            tenant_id: Uuid,
            email: String,
            role: String,
            expires_at: DateTime<Utc>,
            used_at: Option<DateTime<Utc>>,
            revoked_at: Option<DateTime<Utc>>,
        }
        let row: Option<Locked> = sqlx::query_as(
            "SELECT id, tenant_id, email, role, expires_at, used_at, revoked_at
             FROM mokosh_auth.admin_invites
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(&token_hash[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let row = row.ok_or(AuthError::NotFound)?;

        // 2. Refuse if terminal.
        if row.used_at.is_some() {
            return Err(AuthError::Conflict("invite already used".into()));
        }
        if row.revoked_at.is_some() {
            return Err(AuthError::InvalidGrant("invite revoked".into()));
        }
        if row.expires_at < Utc::now() {
            return Err(AuthError::InvalidGrant("invite expired".into()));
        }

        // 3. Insert the user. Active + email-verified because clicking
        //    an emailed link demonstrates inbox control.
        let new_user_id = Uuid::new_v4();
        let user_row: UserRow = sqlx::query_as(
            "INSERT INTO mokosh_auth.users
                (id, tenant_id, email, password_hash, role, status,
                 first_name, last_name, email_verified_at)
             VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, NOW())
             RETURNING id, tenant_id, email, email_verified_at, password_hash,
                       role, status, first_name, last_name, timezone, locale,
                       avatar_url, mfa_enrolled, last_login_at, last_active_tenant,
                       created_at, updated_at",
        )
        .bind(new_user_id)
        .bind(row.tenant_id)
        .bind(&row.email)
        .bind(password_hash)
        .bind(&row.role)
        .bind(first_name)
        .bind(last_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("user already exists for this email".into())
            }
            _ => db_err(e),
        })?;

        // 4. Mark the invite used.
        sqlx::query(
            "UPDATE mokosh_auth.admin_invites
             SET used_at = NOW(), used_by = $1
             WHERE id = $2",
        )
        .bind(new_user_id)
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        let user = User::try_from(user_row)?;
        debug_assert!(matches!(user.status, UserStatus::Active));
        Ok(user)
    }

    async fn accept_existing_once(
        &self,
        token: &str,
        existing_user_id: UserId,
    ) -> Result<User, AuthError> {
        let token_hash = mokosh_auth_crypto::hash_opaque_token(token);
        let mut tx = self.pool.pg().begin().await.map_err(db_err)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        // 1. Lock the invite row (same shape as accept_once).
        #[derive(sqlx::FromRow)]
        struct Locked {
            id: Uuid,
            tenant_id: Uuid,
            email: String,
            role: String,
            expires_at: DateTime<Utc>,
            used_at: Option<DateTime<Utc>>,
            revoked_at: Option<DateTime<Utc>>,
        }
        let row: Option<Locked> = sqlx::query_as(
            "SELECT id, tenant_id, email, role, expires_at, used_at, revoked_at
             FROM mokosh_auth.admin_invites
             WHERE token_hash = $1
             FOR UPDATE",
        )
        .bind(&token_hash[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let row = row.ok_or(AuthError::NotFound)?;

        if row.used_at.is_some() {
            return Err(AuthError::Conflict("invite already used".into()));
        }
        if row.revoked_at.is_some() {
            return Err(AuthError::InvalidGrant("invite revoked".into()));
        }
        if row.expires_at < Utc::now() {
            return Err(AuthError::InvalidGrant("invite expired".into()));
        }

        // 2. Sanity check: the existing user's email must match the
        //    invite's email. The handler already looked the user up
        //    by email globally, but a SERIALIZABLE re-check inside
        //    the tx closes any race where the user's email gets
        //    changed between preview and accept.
        let user_row: UserRow = sqlx::query_as(&format!(
            "{} WHERE id = $1 AND deleted_at IS NULL",
            crate::user::SELECT_USER_PUB
        ))
        .bind(existing_user_id.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::RowNotFound => AuthError::NotFound,
            _ => db_err(e),
        })?;

        let user = User::try_from(user_row)?;
        if user.email.to_lowercase() != row.email.to_lowercase() {
            return Err(AuthError::Forbidden(
                "user email does not match invite".into(),
            ));
        }

        // 3. Insert the membership. Unique-violation on the (user_id,
        //    tenant_id) PK means the user is already a member; we
        //    surface that as Conflict so the handler can render a
        //    "you're already in this tenant" message rather than an
        //    error.
        sqlx::query(
            "INSERT INTO mokosh_auth.memberships
                (user_id, tenant_id, role, status)
             VALUES ($1, $2, $3, 'active')",
        )
        .bind(existing_user_id.0)
        .bind(row.tenant_id)
        .bind(&row.role)
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("user is already a member of this tenant".into())
            }
            _ => db_err(e),
        })?;

        // 4. Mark the invite used.
        sqlx::query(
            "UPDATE mokosh_auth.admin_invites
             SET used_at = NOW(), used_by = $1
             WHERE id = $2",
        )
        .bind(existing_user_id.0)
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(user)
    }
}
