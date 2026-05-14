//! Storage-layer tests for `PgTotpRepository`,
//! `PgRecoveryCodeRepository`, and `PgMfaChallengeRepository`.
//!
//! `#[sqlx::test]` provisions a per-test DB. The dev `mokosh` DB
//! template is fully migrated; if a developer points DATABASE_URL at a
//! bare Postgres we re-run migrations defensively.

use chrono::{Duration, Utc};
use mokosh_auth_core::{
    AuthError, MfaChallengePurpose, MfaChallengeRepository, NewMfaChallenge,
    RecoveryCodeRepository, TenantId, TotpRepository, UserId,
};
use mokosh_auth_storage::{
    run_migrations, AuthPool, PgMfaChallengeRepository, PgRecoveryCodeRepository, PgTotpRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    auth_pool: AuthPool,
    user_id: UserId,
    tenant_id: TenantId,
}

async fn setup(pool: PgPool) -> Fixture {
    sqlx::query(r#"CREATE EXTENSION IF NOT EXISTS "uuid-ossp""#)
        .execute(&pool)
        .await
        .expect("uuid-ossp");
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
    .expect("public.tenants");

    let auth_pool = AuthPool::from_pool(pool.clone());
    let auth_schema_present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables
                         WHERE table_schema = 'mokosh_auth'
                           AND table_name = 'mfa_challenges')",
    )
    .fetch_one(&pool)
    .await
    .expect("schema check");
    if !auth_schema_present {
        run_migrations(&auth_pool).await.expect("migrations");
    }

    let tenant_id: Uuid =
        sqlx::query_scalar("INSERT INTO public.tenants (name, slug) VALUES ($1, $2) RETURNING id")
            .bind("MFA Test Tenant")
            .bind(format!("t-{}", Uuid::new_v4()))
            .fetch_one(&pool)
            .await
            .expect("insert tenant");

    let email = format!("mfa-{}@example.com", Uuid::new_v4());
    let pw_hash = mokosh_auth_crypto::hash_password("Sup3rL0ngPass!").expect("hash");
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mokosh_auth.users
            (tenant_id, email, password_hash, role, status, email_verified_at)
         VALUES ($1, $2, $3, 'admin', 'active', NOW())
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(&email)
    .bind(&pw_hash)
    .fetch_one(&pool)
    .await
    .expect("insert user");

    Fixture {
        pool,
        auth_pool,
        user_id: UserId(user_id),
        tenant_id: TenantId(tenant_id),
    }
}

fn fake_encrypted_blob() -> serde_json::Value {
    serde_json::json!({
        "version":    1,
        "nonce":      vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        "ciphertext": vec![0xabu8; 20],
    })
}

#[sqlx::test]
async fn start_enrollment_inserts_new(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgTotpRepository::new(fx.auth_pool.clone());

    let e = repo
        .start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .expect("start_enrollment");
    assert_eq!(e.user_id, fx.user_id);
    assert_eq!(e.tenant_id, fx.tenant_id);
    assert!(e.confirmed_at.is_none());
    assert_eq!(e.key_version, 1);
}

#[sqlx::test]
async fn start_enrollment_rotates_unconfirmed_secret(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgTotpRepository::new(fx.auth_pool.clone());

    let first = repo
        .start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    let new_blob = serde_json::json!({
        "version":    1,
        "nonce":      vec![9u8; 12],
        "ciphertext": vec![0xcdu8; 20],
    });
    let second = repo
        .start_enrollment(fx.user_id, fx.tenant_id, new_blob.clone(), 1)
        .await
        .unwrap();
    assert_eq!(first.id, second.id, "no new row inserted");
    assert_eq!(second.secret_encrypted, new_blob, "secret was rotated");
}

#[sqlx::test]
async fn start_enrollment_conflict_when_confirmed(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgTotpRepository::new(fx.auth_pool.clone());

    repo.start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    repo.confirm(fx.user_id).await.unwrap();
    let err = repo
        .start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .expect_err("should conflict");
    assert!(matches!(err, AuthError::Conflict(_)), "got {err:?}");
}

#[sqlx::test]
async fn confirm_flips_mfa_enrolled_after_recovery_codes_seeded(pool: PgPool) {
    let fx = setup(pool).await;
    let totp = PgTotpRepository::new(fx.auth_pool.clone());
    let recov = PgRecoveryCodeRepository::new(fx.auth_pool.clone());

    let enrollment = totp
        .start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    let hashes: Vec<[u8; 32]> = (0..10).map(|i| [i as u8; 32]).collect();
    recov
        .replace_all(fx.user_id, fx.tenant_id, enrollment.id, &hashes)
        .await
        .unwrap();
    totp.confirm(fx.user_id).await.unwrap();

    let mfa: bool = sqlx::query_scalar("SELECT mfa_enrolled FROM mokosh_auth.users WHERE id = $1")
        .bind(fx.user_id.0)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert!(mfa);
    assert_eq!(recov.count_unused(fx.user_id).await.unwrap(), 10);
}

#[sqlx::test]
async fn confirm_twice_is_conflict(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgTotpRepository::new(fx.auth_pool.clone());

    repo.start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    repo.confirm(fx.user_id).await.unwrap();
    let err = repo
        .confirm(fx.user_id)
        .await
        .expect_err("second confirm must fail");
    assert!(matches!(err, AuthError::Conflict(_)), "got {err:?}");
}

#[sqlx::test]
async fn consume_step_is_strictly_increasing(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgTotpRepository::new(fx.auth_pool.clone());
    repo.start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();

    repo.consume_step(fx.user_id, 1000).await.unwrap();
    let err = repo
        .consume_step(fx.user_id, 1000)
        .await
        .expect_err("same step must be rejected");
    assert!(matches!(err, AuthError::InvalidGrant(_)));
    let err = repo
        .consume_step(fx.user_id, 999)
        .await
        .expect_err("earlier step must be rejected");
    assert!(matches!(err, AuthError::InvalidGrant(_)));
    repo.consume_step(fx.user_id, 1001).await.unwrap();
}

#[sqlx::test]
async fn disenroll_is_idempotent_and_sets_banner(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgTotpRepository::new(fx.auth_pool.clone());

    repo.start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    repo.confirm(fx.user_id).await.unwrap();

    repo.disenroll(fx.user_id).await.unwrap();
    repo.disenroll(fx.user_id).await.unwrap(); // idempotent

    let (mfa, banner): (bool, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT mfa_enrolled, mfa_disenrolled_at FROM mokosh_auth.users WHERE id = $1",
    )
    .bind(fx.user_id.0)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert!(!mfa);
    assert!(banner.is_some());
}

#[sqlx::test]
async fn confirm_clears_mfa_disenrolled_banner(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgTotpRepository::new(fx.auth_pool.clone());

    // Plant a stale banner.
    sqlx::query("UPDATE mokosh_auth.users SET mfa_disenrolled_at = NOW() WHERE id = $1")
        .bind(fx.user_id.0)
        .execute(&fx.pool)
        .await
        .unwrap();

    repo.start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    repo.confirm(fx.user_id).await.unwrap();

    let banner: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT mfa_disenrolled_at FROM mokosh_auth.users WHERE id = $1")
            .bind(fx.user_id.0)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert!(banner.is_none(), "banner must be cleared on re-enrollment");
}

#[sqlx::test]
async fn recovery_code_consume_then_replay_is_not_found(pool: PgPool) {
    let fx = setup(pool).await;
    let totp = PgTotpRepository::new(fx.auth_pool.clone());
    let recov = PgRecoveryCodeRepository::new(fx.auth_pool.clone());

    let code_hash = [0x42u8; 32];
    let enrollment = totp
        .start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    recov
        .replace_all(fx.user_id, fx.tenant_id, enrollment.id, &[code_hash])
        .await
        .unwrap();
    totp.confirm(fx.user_id).await.unwrap();

    recov.consume_unused(fx.user_id, code_hash).await.unwrap();
    let err = recov
        .consume_unused(fx.user_id, code_hash)
        .await
        .expect_err("second consume must fail");
    assert!(matches!(err, AuthError::NotFound));
}

#[sqlx::test]
async fn recovery_replace_all_wipes_old(pool: PgPool) {
    let fx = setup(pool).await;
    let totp = PgTotpRepository::new(fx.auth_pool.clone());
    let recov = PgRecoveryCodeRepository::new(fx.auth_pool.clone());

    let old: Vec<[u8; 32]> = (0..10).map(|i| [i; 32]).collect();
    let enrollment = totp
        .start_enrollment(fx.user_id, fx.tenant_id, fake_encrypted_blob(), 1)
        .await
        .unwrap();
    recov
        .replace_all(fx.user_id, fx.tenant_id, enrollment.id, &old)
        .await
        .unwrap();
    totp.confirm(fx.user_id).await.unwrap();
    assert_eq!(recov.count_unused(fx.user_id).await.unwrap(), 10);

    let new: Vec<[u8; 32]> = (50..60).map(|i| [i; 32]).collect();
    recov
        .replace_all(fx.user_id, fx.tenant_id, enrollment.id, &new)
        .await
        .unwrap();
    assert_eq!(recov.count_unused(fx.user_id).await.unwrap(), 10);

    let err = recov
        .consume_unused(fx.user_id, old[0])
        .await
        .expect_err("old must be gone");
    assert!(matches!(err, AuthError::NotFound));
    recov.consume_unused(fx.user_id, new[0]).await.unwrap();
}

#[sqlx::test]
async fn mfa_challenge_round_trip(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgMfaChallengeRepository::new(fx.auth_pool.clone());

    let token_hash = [0xa1u8; 32];
    let c = repo
        .issue(NewMfaChallenge {
            user_id: fx.user_id,
            tenant_id: fx.tenant_id,
            token_hash,
            client_id: None,
            scope: vec!["openid".into()],
            active_tenant_id: fx.tenant_id,
            purpose: MfaChallengePurpose::Login,
            expires_at: Utc::now() + Duration::minutes(5),
            ip: None,
            user_agent: None,
        })
        .await
        .unwrap();
    assert_eq!(c.purpose, MfaChallengePurpose::Login);

    let found = repo.find_by_token_hash(token_hash).await.unwrap().unwrap();
    assert_eq!(found.id, c.id);

    let consumed = repo
        .consume(token_hash, MfaChallengePurpose::Login)
        .await
        .unwrap();
    assert!(consumed.consumed_at.is_some());

    let err = repo
        .consume(token_hash, MfaChallengePurpose::Login)
        .await
        .expect_err("second consume");
    assert!(matches!(err, AuthError::NotFound));
}

#[sqlx::test]
async fn mfa_challenge_wrong_purpose_is_not_found(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgMfaChallengeRepository::new(fx.auth_pool.clone());
    let token_hash = [0xc3u8; 32];
    repo.issue(NewMfaChallenge {
        user_id: fx.user_id,
        tenant_id: fx.tenant_id,
        token_hash,
        client_id: None,
        scope: vec![],
        active_tenant_id: fx.tenant_id,
        purpose: MfaChallengePurpose::Login,
        expires_at: Utc::now() + Duration::minutes(5),
        ip: None,
        user_agent: None,
    })
    .await
    .unwrap();

    let err = repo
        .consume(token_hash, MfaChallengePurpose::StepUp)
        .await
        .expect_err("wrong purpose");
    assert!(matches!(err, AuthError::NotFound));
}

#[sqlx::test]
async fn mfa_challenge_expired_is_not_found(pool: PgPool) {
    let fx = setup(pool).await;
    let repo = PgMfaChallengeRepository::new(fx.auth_pool.clone());
    let token_hash = [0xefu8; 32];
    repo.issue(NewMfaChallenge {
        user_id: fx.user_id,
        tenant_id: fx.tenant_id,
        token_hash,
        client_id: None,
        scope: vec![],
        active_tenant_id: fx.tenant_id,
        purpose: MfaChallengePurpose::Login,
        expires_at: Utc::now() - Duration::seconds(1),
        ip: None,
        user_agent: None,
    })
    .await
    .unwrap();

    let err = repo
        .consume(token_hash, MfaChallengePurpose::Login)
        .await
        .expect_err("expired");
    assert!(matches!(err, AuthError::NotFound));
}
