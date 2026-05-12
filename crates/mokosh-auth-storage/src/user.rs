//! Postgres-backed `UserRepository`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{
    AuthError, NewUser, TenantId, User, UserId, UserRepository, UserStatus,
};

use crate::conv::{db_err, UserRow};
use crate::pool::AuthPool;

pub(crate) const SELECT_USER_PUB: &str = SELECT_USER;
const SELECT_USER: &str = r#"
    SELECT id, tenant_id, email, email_verified_at, password_hash,
           role, status, first_name, last_name, timezone, locale,
           avatar_url, mfa_enrolled, last_login_at, last_active_tenant,
           created_at, updated_at
    FROM mokosh_auth.users
"#;

pub struct PgUserRepository {
    pool: AuthPool,
}

impl PgUserRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, AuthError> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "{SELECT_USER} WHERE id = $1 AND deleted_at IS NULL"
        ))
        .bind(id.0)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(User::try_from).transpose()
    }

    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, AuthError> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "{SELECT_USER} WHERE tenant_id = $1 AND email = $2 AND deleted_at IS NULL"
        ))
        .bind(tenant_id.0)
        .bind(email)
        .fetch_optional(self.pool.pg())
        .await
        .map_err(db_err)?;
        row.map(User::try_from).transpose()
    }

    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<User>, AuthError> {
        let rows: Vec<UserRow> = sqlx::query_as(&format!(
            "{SELECT_USER}
             WHERE tenant_id = $1 AND deleted_at IS NULL
             ORDER BY created_at DESC"
        ))
        .bind(tenant_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(User::try_from).collect()
    }

    async fn find_by_email_globally(&self, email: &str) -> Result<Vec<User>, AuthError> {
        // LIMIT 2: we only need to distinguish "exactly one match" from
        // "ambiguous" (>= 2). No reason to read more rows than that.
        // Restrict to active accounts so deactivated users in tenant A
        // do not block sign-in for the same email in tenant B.
        let rows: Vec<UserRow> = sqlx::query_as(&format!(
            "{SELECT_USER}
             WHERE email = $1
               AND deleted_at IS NULL
               AND status = 'active'
             LIMIT 2"
        ))
        .bind(email)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(User::try_from).collect()
    }

    async fn create(&self, new: NewUser) -> Result<User, AuthError> {
        let row: UserRow = sqlx::query_as(&format!(
            "INSERT INTO mokosh_auth.users
                (tenant_id, email, password_hash, role, status, first_name, last_name)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, tenant_id, email, email_verified_at, password_hash,
                       role, status, first_name, last_name, timezone, locale,
                       avatar_url, mfa_enrolled, last_login_at, last_active_tenant,
                       created_at, updated_at"
        ))
        .bind(new.tenant_id.0)
        .bind(&new.email)
        .bind(&new.password_hash)
        .bind(new.role.as_str())
        .bind(new.status.as_str())
        .bind(&new.first_name)
        .bind(&new.last_name)
        .fetch_one(self.pool.pg())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AuthError::Conflict("email already registered for this tenant".into())
            }
            _ => db_err(e),
        })?;
        User::try_from(row)
    }

    async fn update_last_login(&self, id: UserId, at: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("UPDATE mokosh_auth.users SET last_login_at = $1, updated_at = NOW() WHERE id = $2")
            .bind(at)
            .bind(id.0)
            .execute(self.pool.pg())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn set_password_hash(&self, id: UserId, hash: &str) -> Result<(), AuthError> {
        sqlx::query("UPDATE mokosh_auth.users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(hash)
            .bind(id.0)
            .execute(self.pool.pg())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn record_failed_login(
        &self,
        id: UserId,
        threshold: i32,
        lock_for: chrono::Duration,
    ) -> Result<mokosh_auth_core::FailedLoginOutcome, AuthError> {
        let lock_for_secs = lock_for.num_seconds().max(0);
        // Increment + conditionally set locked_until in one statement so
        // parallel failed-logins do not race the threshold check.
        let row: (i32, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            "UPDATE mokosh_auth.users
             SET failed_login_count = failed_login_count + 1,
                 last_failed_login_at = NOW(),
                 locked_until = CASE
                     WHEN failed_login_count + 1 >= $2 THEN NOW() + ($3 || ' seconds')::INTERVAL
                     ELSE locked_until
                 END,
                 updated_at = NOW()
             WHERE id = $1
             RETURNING failed_login_count, locked_until",
        )
        .bind(id.0)
        .bind(threshold)
        .bind(lock_for_secs.to_string())
        .fetch_one(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(mokosh_auth_core::FailedLoginOutcome {
            failed_login_count: row.0,
            locked_until: row.1,
        })
    }

    async fn clear_failed_logins(&self, id: UserId) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE mokosh_auth.users
             SET failed_login_count = 0,
                 last_failed_login_at = NULL,
                 locked_until = NULL,
                 updated_at = NOW()
             WHERE id = $1",
        )
        .bind(id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn lockout_status(
        &self,
        id: UserId,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, AuthError> {
        let row: Option<Option<chrono::DateTime<chrono::Utc>>> =
            sqlx::query_scalar("SELECT locked_until FROM mokosh_auth.users WHERE id = $1")
                .bind(id.0)
                .fetch_optional(self.pool.pg())
                .await
                .map_err(db_err)?;
        Ok(row.flatten())
    }

    async fn update_profile(
        &self,
        id: UserId,
        first_name: Option<&str>,
        last_name: Option<&str>,
        timezone: &str,
        avatar_url: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE mokosh_auth.users
             SET first_name = $1,
                 last_name = $2,
                 timezone = $3,
                 avatar_url = $4,
                 updated_at = NOW()
             WHERE id = $5",
        )
        .bind(first_name)
        .bind(last_name)
        .bind(timezone)
        .bind(avatar_url)
        .bind(id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn set_status(&self, id: UserId, status: UserStatus) -> Result<(), AuthError> {
        sqlx::query("UPDATE mokosh_auth.users SET status = $1, updated_at = NOW() WHERE id = $2")
            .bind(status.as_str())
            .bind(id.0)
            .execute(self.pool.pg())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn set_last_active_tenant(
        &self,
        id: UserId,
        tenant_id: Option<mokosh_auth_core::TenantId>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE mokosh_auth.users
             SET last_active_tenant = $1, updated_at = NOW()
             WHERE id = $2",
        )
        .bind(tenant_id.map(|t| t.0))
        .bind(id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn mark_email_verified(&self, id: UserId, at: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE mokosh_auth.users
             SET email_verified_at = $1, updated_at = NOW()
             WHERE id = $2 AND email_verified_at IS NULL",
        )
        .bind(at)
        .bind(id.0)
        .execute(self.pool.pg())
        .await
        .map_err(db_err)?;
        Ok(())
    }
}
