//! MAPPS-475 (MAPPS-474 phase 1): read helpers for `identities` and
//! `tenant_memberships`.
//!
//! Phase 1 does NOT wire these into any handler; the auth service still
//! reads from `users`. Phase 2 will call [`IdentityRepo::find_by_email`]
//! from the new `GET /api/v1/auth/memberships` endpoint, and phase 3 will
//! call it from the refactored login handler.
//!
//! Both tables are cross-tenant lookup tables (no RLS, see
//! `migrations/128_identities_and_memberships.sql`), so every read here
//! runs on the migrator pool with no `app.current_tenant` GUC required.

use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub phone: Option<String>,
    pub mobile: Option<String>,
    pub avatar_url: Option<String>,
    pub timezone: String,
    pub locale: String,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub notification_preferences: serde_json::Value,
    pub settings: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub struct IdentityRepo;

impl IdentityRepo {
    pub async fn find_by_email(
        pool: &PgPool,
        email: &str,
    ) -> Result<Option<IdentityRow>, sqlx::Error> {
        sqlx::query_as::<_, IdentityRow>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, phone, mobile,
                   avatar_url, timezone, locale, email_verified_at, last_login_at,
                   mfa_enabled, mfa_secret, notification_preferences, settings,
                   status, created_at, updated_at
            FROM identities
            WHERE lower(email) = lower($1)
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
        sqlx::query_as::<_, IdentityRow>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, phone, mobile,
                   avatar_url, timezone, locale, email_verified_at, last_login_at,
                   mfa_enabled, mfa_secret, notification_preferences, settings,
                   status, created_at, updated_at
            FROM identities
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MembershipRow {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub title: Option<String>,
    pub status: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub struct MembershipRepo;

impl MembershipRepo {
    /// Every active membership for an identity, ordered by joined_at so
    /// the picker in phase 3 renders "your longest-standing tenant first".
    pub async fn list_active_for_identity(
        pool: &PgPool,
        identity_id: Uuid,
    ) -> Result<Vec<MembershipRow>, sqlx::Error> {
        sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT id, identity_id, tenant_id, role, title, status,
                   joined_at, last_active_at, created_at, updated_at
            FROM tenant_memberships
            WHERE identity_id = $1 AND status = 'active'
            ORDER BY joined_at ASC
            "#,
        )
        .bind(identity_id)
        .fetch_all(pool)
        .await
    }

    pub async fn find(
        pool: &PgPool,
        identity_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<MembershipRow>, sqlx::Error> {
        sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT id, identity_id, tenant_id, role, title, status,
                   joined_at, last_active_at, created_at, updated_at
            FROM tenant_memberships
            WHERE identity_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }
}
