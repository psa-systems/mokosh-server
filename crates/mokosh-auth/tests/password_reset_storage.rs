//! Storage-layer tests for `PgPasswordResetTokenRepository::complete`.
//!
//! Each test gets a fresh database via `#[sqlx::test]`. We apply the
//! mokosh-auth migrations through `run_migrations`, plant a minimal
//! `public.tenants` table + tenant + user, and drive the repo directly
//! without standing up the HTTP layer.
//!
//! Coverage (per docs/mokosh-smtp/05-password-reset.md):
//!   - happy path: token completes, password rotates, sessions revoked,
//!     refresh families revoked, token marked used
//!   - double-submit: completing the same token twice returns NotFound
//!   - expired: completing a token whose `expires_at` is in the past
//!     returns NotFound, even though `used_at IS NULL`
//!   - missing user: token whose email no longer matches any user
//!     (account deleted between issue and complete) returns NotFound

use chrono::{Duration, Utc};
use mokosh_auth_core::{NewPasswordResetToken, PasswordResetTokenRepository};
use mokosh_auth_storage::{run_migrations, AuthPool, PgPasswordResetTokenRepository};
use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    repo: PgPasswordResetTokenRepository,
    pool: PgPool,
    user_id: Uuid,
    tenant_id: Uuid,
    email: String,
    old_password_hash: String,
}

async fn setup(pool: PgPool) -> Fixture {
    sqlx::query(r#"CREATE EXTENSION IF NOT EXISTS "uuid-ossp""#)
        .execute(&pool)
        .await
        .expect("create uuid-ossp");
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS public.tenants (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name VARCHAR(255) NOT NULL,
            slug VARCHAR(100) NOT NULL UNIQUE,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )"#,
    )
    .execute(&pool)
    .await
    .expect("create public.tenants");

    // `#[sqlx::test]` clones the template database (the one DATABASE_URL
    // points at), which in dev-sso already has all mokosh_auth migrations
    // applied. We only re-run them when the clone came up empty - belt
    // and braces in case a future operator points DATABASE_URL at a
    // bare DB.
    let auth_pool = AuthPool::from_pool(pool.clone());
    let auth_schema_present: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'mokosh_auth' AND table_name = 'password_reset_tokens'
         )",
    )
    .fetch_one(&pool)
    .await
    .expect("check schema");
    if !auth_schema_present {
        run_migrations(&auth_pool).await.expect("migrations");
    }

    let tenant_id: Uuid =
        sqlx::query_scalar("INSERT INTO public.tenants (name, slug) VALUES ($1, $2) RETURNING id")
            .bind("PWReset Tenant")
            .bind(format!("t-{}", Uuid::new_v4()))
            .fetch_one(&pool)
            .await
            .expect("insert tenant");

    let email = format!("user-{}@example.com", Uuid::new_v4());
    let old_password_hash =
        mokosh_auth_crypto::hash_password("OldP4ssw0rd!Strong").expect("hash old pw");
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mokosh_auth.users
            (tenant_id, email, password_hash, role, status, email_verified_at)
         VALUES ($1, $2, $3, 'admin', 'active', NOW())
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(&email)
    .bind(&old_password_hash)
    .fetch_one(&pool)
    .await
    .expect("insert user");

    Fixture {
        repo: PgPasswordResetTokenRepository::new(auth_pool),
        pool,
        user_id,
        tenant_id,
        email,
        old_password_hash,
    }
}

fn make_token() -> ([u8; 32], NewPasswordResetToken, String) {
    let raw = mokosh_auth_crypto::generate_opaque_token();
    let hash = mokosh_auth_crypto::hash_opaque_token(&raw);
    (
        hash,
        NewPasswordResetToken {
            email: String::new(), // caller fills
            token_hash: hash,
            expires_at: Utc::now() + Duration::hours(1),
        },
        raw,
    )
}

#[sqlx::test]
async fn complete_happy_path_rotates_password_and_boots_sessions(pool: PgPool) {
    let fx = setup(pool).await;

    let (hash, mut new_token, _raw) = make_token();
    new_token.email = fx.email.clone();
    fx.repo.issue(new_token).await.expect("issue");

    // Plant an active op_session and an active refresh_token_family so we
    // can prove they get revoked.
    let session_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mokosh_auth.op_sessions (sid, user_id, tenant_id, expires_at)
         VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')
         RETURNING id",
    )
    .bind(format!("sid-{}", Uuid::new_v4()))
    .bind(fx.user_id)
    .bind(fx.tenant_id)
    .fetch_one(&fx.pool)
    .await
    .expect("insert op_session");

    // refresh_token_families.client_id has an FK into oauth_clients, so we
    // have to plant a minimal client row first.
    let client_id = Uuid::new_v4();
    let client_secret_hash = mokosh_auth_crypto::hash_password("client-secret").expect("hash");
    sqlx::query(
        "INSERT INTO mokosh_auth.oauth_clients
            (client_id, client_type, client_secret_hash, name,
             redirect_uris, post_logout_redirect_uris,
             allowed_scopes, allowed_grant_types,
             token_endpoint_auth_method, audience)
         VALUES ($1, 'confidential', $2, 'pw-reset-test-client',
                 ARRAY['http://127.0.0.1']::TEXT[],
                 ARRAY['http://127.0.0.1/']::TEXT[],
                 ARRAY['openid']::TEXT[],
                 ARRAY['authorization_code','refresh_token']::TEXT[],
                 'client_secret_basic', 'http://api.test.local')",
    )
    .bind(client_id)
    .bind(&client_secret_hash)
    .execute(&fx.pool)
    .await
    .expect("insert oauth_client");

    let family_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mokosh_auth.refresh_token_families
            (client_id, user_id, tenant_id, op_session_id)
         VALUES ($1, $2, $3, $4)
         RETURNING id",
    )
    .bind(client_id)
    .bind(fx.user_id)
    .bind(fx.tenant_id)
    .bind(session_id)
    .fetch_one(&fx.pool)
    .await
    .expect("insert refresh_token_family");

    let new_hash = mokosh_auth_crypto::hash_password("Brand-NewPass!42").expect("hash");
    let user_id = fx
        .repo
        .complete(hash, &new_hash)
        .await
        .expect("complete should succeed");
    assert_eq!(user_id.0, fx.user_id);

    // Password row was actually rotated.
    let stored: String =
        sqlx::query_scalar("SELECT password_hash FROM mokosh_auth.users WHERE id = $1")
            .bind(fx.user_id)
            .fetch_one(&fx.pool)
            .await
            .expect("select password_hash");
    assert_eq!(stored, new_hash);
    assert_ne!(stored, fx.old_password_hash);

    // Token is marked used and pinned to the user.
    let (used_at, token_user_id): (Option<chrono::DateTime<Utc>>, Option<Uuid>) = sqlx::query_as(
        "SELECT used_at, user_id FROM mokosh_auth.password_reset_tokens WHERE token_hash = $1",
    )
    .bind(&hash[..])
    .fetch_one(&fx.pool)
    .await
    .expect("select reset token");
    assert!(used_at.is_some(), "token should be marked used");
    assert_eq!(token_user_id, Some(fx.user_id));

    // op_session revoked.
    let session_revoked: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM mokosh_auth.op_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&fx.pool)
            .await
            .expect("select op_session");
    assert!(session_revoked.is_some(), "op_session must be revoked");

    // refresh family revoked with reason.
    let (fam_revoked, fam_reason): (Option<chrono::DateTime<Utc>>, Option<String>) =
        sqlx::query_as(
            "SELECT revoked_at, revoke_reason
             FROM mokosh_auth.refresh_token_families WHERE id = $1",
        )
        .bind(family_id)
        .fetch_one(&fx.pool)
        .await
        .expect("select family");
    assert!(fam_revoked.is_some(), "refresh family must be revoked");
    assert_eq!(fam_reason.as_deref(), Some("password_reset"));
}

#[sqlx::test]
async fn complete_twice_returns_not_found_on_second_call(pool: PgPool) {
    let fx = setup(pool).await;

    let (hash, mut new_token, _raw) = make_token();
    new_token.email = fx.email.clone();
    fx.repo.issue(new_token).await.expect("issue");

    let new_hash = mokosh_auth_crypto::hash_password("Brand-NewPass!42").expect("hash");
    fx.repo.complete(hash, &new_hash).await.expect("first complete");

    let second_hash = mokosh_auth_crypto::hash_password("Yet-Another!42").expect("hash");
    let err = fx
        .repo
        .complete(hash, &second_hash)
        .await
        .expect_err("second complete must fail");
    assert!(
        matches!(err, mokosh_auth_core::AuthError::NotFound),
        "second complete should be NotFound, got {err:?}"
    );

    // Password should still equal the first reset's value, not the second.
    let stored: String =
        sqlx::query_scalar("SELECT password_hash FROM mokosh_auth.users WHERE id = $1")
            .bind(fx.user_id)
            .fetch_one(&fx.pool)
            .await
            .expect("select password_hash");
    assert_eq!(stored, new_hash);
}

#[sqlx::test]
async fn expired_token_returns_not_found(pool: PgPool) {
    let fx = setup(pool).await;

    let raw = mokosh_auth_crypto::generate_opaque_token();
    let hash = mokosh_auth_crypto::hash_opaque_token(&raw);
    fx.repo
        .issue(NewPasswordResetToken {
            email: fx.email.clone(),
            token_hash: hash,
            // Already expired by the time it's issued. The repo trusts
            // the caller for `expires_at`, so this is the cleanest way
            // to simulate a stale token without sleeping.
            expires_at: Utc::now() - Duration::minutes(1),
        })
        .await
        .expect("issue");

    let new_hash = mokosh_auth_crypto::hash_password("Brand-NewPass!42").expect("hash");
    let err = fx
        .repo
        .complete(hash, &new_hash)
        .await
        .expect_err("expired complete must fail");
    assert!(
        matches!(err, mokosh_auth_core::AuthError::NotFound),
        "expired complete should be NotFound, got {err:?}"
    );

    // Password unchanged.
    let stored: String =
        sqlx::query_scalar("SELECT password_hash FROM mokosh_auth.users WHERE id = $1")
            .bind(fx.user_id)
            .fetch_one(&fx.pool)
            .await
            .expect("select password_hash");
    assert_eq!(stored, fx.old_password_hash);
}

#[sqlx::test]
async fn complete_returns_not_found_when_user_gone(pool: PgPool) {
    let fx = setup(pool).await;

    let (hash, mut new_token, _raw) = make_token();
    new_token.email = fx.email.clone();
    fx.repo.issue(new_token).await.expect("issue");

    // Soft-delete the user. The complete query filters on deleted_at IS NULL,
    // so it should now report NotFound rather than rotating a tombstoned row.
    sqlx::query("UPDATE mokosh_auth.users SET deleted_at = NOW() WHERE id = $1")
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("soft-delete user");

    let new_hash = mokosh_auth_crypto::hash_password("Brand-NewPass!42").expect("hash");
    let err = fx
        .repo
        .complete(hash, &new_hash)
        .await
        .expect_err("complete must fail when user gone");
    assert!(
        matches!(err, mokosh_auth_core::AuthError::NotFound),
        "complete should be NotFound when user soft-deleted, got {err:?}"
    );
}
