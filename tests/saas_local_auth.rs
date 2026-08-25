//! PMS-905: the local password stops being a credential when, and only when,
//! a working alternative exists.
//!
//! PMS-904 stopped the mail that supports the local platform password in `saas`
//! deployments. That left the endpoints themselves reachable, and one of them
//! reported success while doing nothing: `/auth/forgot-password` answers `200`
//! unconditionally, by design, so it never reveals whether an address has an
//! account. With the mail suppressed, that becomes a customer being told a link
//! is on its way that is never sent. This closes the entry points instead.
//!
//! The condition is a conjunction, and the second half is the whole point.
//! `saas` alone is not enough: a deployment whose OIDC configuration is missing
//! or broken cannot authenticate anyone through SSO, so closing the local path
//! behind it leaves no way in at all. That is the PMS-289 shape - a
//! misconfigured IdP made fatal, which took staging and production down and
//! needed PMS-292 to restore service. Every test below is therefore run in both
//! SSO postures, because a gate that ignored the verifier would pass the first
//! half of this file and fail the second.
//!
//! What stays open in every mode: the portal plane (a `contacts` identity, not
//! federated through bunyip in either mode, PMS-820), and `/auth/refresh` for a
//! session that already exists.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::auth::AuthService;
use mokosh_server::utils::deployment::DeploymentMode;
use mokosh_server::utils::error::AppError;
use mokosh_server::Database;
use mokosh_types::auth::{LoginRequest, ResetPasswordRequest};

const PASSWORD: &str = "local-password-123";

fn service(pool: &PgPool, mode: DeploymentMode, sso_mounted: bool) -> AuthService {
    AuthService::with_mailer(
        Database::from_pool(pool.clone()),
        "test-jwt-secret-please-change".to_string(),
        std::sync::Arc::new(mokosh_server::utils::email::LogMailer),
        "http://localhost:4301".to_string(),
    )
    .with_deployment_mode(mode)
    .with_sso_mounted(sso_mounted)
}

/// A user with a local password: the shape a self-hosted deployment has, and
/// the only shape that can reach the password branch at all.
async fn seed_local_user(pool: &PgPool, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = mokosh_server::utils::crypto::hash_password(PASSWORD).expect("hash");
    sqlx::query(
        r#"
        INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
        VALUES ($1, $2, $3, $4, 'Local', 'User', 'admin', 'active')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed user");
    id
}

fn login_request(email: &str) -> LoginRequest {
    LoginRequest {
        email: email.to_string(),
        password: PASSWORD.to_string(),
        remember_me: false,
        mfa_code: None,
        recovery_code: None,
        approval_code: None,
        device_id: None,
        tenant_id: Some(common::DEFAULT_TENANT_ID),
    }
}

/// The configuration a SaaS deployment actually runs in: mode `saas`, verifier
/// mounted. All three local-credential entry points refuse.
#[sqlx::test]
async fn saas_with_sso_refuses_every_local_credential_entry_point(pool: PgPool) {
    let email = "closed@example.test";
    seed_local_user(&pool, email).await;
    let svc = service(&pool, DeploymentMode::Saas, true);

    let login = svc.login(&login_request(email), None, None).await;
    assert!(
        matches!(login, Err(AppError::Forbidden(_))),
        "the password branch must refuse rather than mint a session, got {login:?}"
    );

    let forgot = svc
        .request_password_reset(Some(common::DEFAULT_TENANT_ID), email)
        .await;
    assert!(
        matches!(forgot, Err(AppError::Forbidden(_))),
        "a reset request that reports success and sends nothing is the dead end this \
         issue removes, got {forgot:?}"
    );

    let redeem = svc
        .reset_password(&ResetPasswordRequest {
            token: format!("{}.whatever", Uuid::new_v4()),
            new_password: "a-new-password-12".to_string(),
            confirm_password: "a-new-password-12".to_string(),
        })
        .await;
    assert!(
        matches!(redeem, Err(AppError::Forbidden(_))),
        "a token minted before the switchover would otherwise set a password that signs \
         nobody in, and say so cheerfully, got {redeem:?}"
    );
}

/// The refusal is one message across all three, so a customer who tries the
/// password box, then "forgot password", then their old link is told the same
/// thing three times rather than assembling three guesses.
#[sqlx::test]
async fn the_three_refusals_say_the_same_thing_and_name_single_sign_on(pool: PgPool) {
    let email = "consistent@example.test";
    seed_local_user(&pool, email).await;
    let svc = service(&pool, DeploymentMode::Saas, true);

    let mut messages = Vec::new();
    for got in [
        svc.login(&login_request(email), None, None)
            .await
            .map(|_| ()),
        svc.request_password_reset(Some(common::DEFAULT_TENANT_ID), email)
            .await,
        svc.reset_password(&ResetPasswordRequest {
            token: format!("{}.whatever", Uuid::new_v4()),
            new_password: "a-new-password-12".to_string(),
            confirm_password: "a-new-password-12".to_string(),
        })
        .await,
    ] {
        match got {
            Err(AppError::Forbidden(m)) => messages.push(m),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    assert!(
        messages.windows(2).all(|w| w[0] == w[1]),
        "the three entry points must give one answer, got {messages:?}"
    );
    let said = messages[0].to_lowercase();
    assert!(
        said.contains("single sign-on"),
        "the refusal has to say what to do instead, or it is just a closed door: {said:?}"
    );
    assert!(
        !said.contains("password is incorrect") && !said.contains("try again"),
        "it must not read as a credential failure the caller could retry past: {said:?}"
    );
}

/// The break-glass. `saas` with no verifier can authenticate nobody through
/// SSO, so the local path stays open: closing it would leave the deployment
/// with no way in at all, which is PMS-289 rather than a security improvement.
#[sqlx::test]
async fn saas_without_sso_keeps_the_local_path_as_the_only_way_in(pool: PgPool) {
    let email = "breakglass@example.test";
    seed_local_user(&pool, email).await;
    let svc = service(&pool, DeploymentMode::Saas, false);

    let login = svc.login(&login_request(email), None, None).await;
    assert!(
        login.is_ok(),
        "with no verifier mounted this is the only credential the instance has; refusing \
         it locks the operator out of their own deployment, got {login:?}"
    );

    // And the recovery path for it stays open too. Suppressing the reset mail
    // on the mode alone would leave a break-glass login nobody could recover a
    // password for, which is the same silent dead end one layer down.
    let forgot = svc
        .request_password_reset(Some(common::DEFAULT_TENANT_ID), email)
        .await;
    assert!(
        forgot.is_ok(),
        "a usable local login needs a usable local reset, got {forgot:?}"
    );
}

/// Self-hosted is untouched by both halves of the condition. The verifier being
/// mounted is not on its own a reason to close anything: a self-hosted operator
/// may run SSO alongside local accounts and expect both to work.
#[sqlx::test]
async fn self_hosted_is_unaffected_with_or_without_sso(pool: PgPool) {
    for (i, sso) in [false, true].into_iter().enumerate() {
        let email = format!("selfhosted{i}@example.test");
        seed_local_user(&pool, &email).await;
        let svc = service(&pool, DeploymentMode::SelfHosted, sso);

        assert!(
            svc.login(&login_request(&email), None, None).await.is_ok(),
            "self-hosted login must work with sso_mounted={sso}"
        );
        assert!(
            svc.request_password_reset(Some(common::DEFAULT_TENANT_ID), &email)
                .await
                .is_ok(),
            "self-hosted reset must work with sso_mounted={sso}"
        );
    }
}

/// The population the refusal actually affects is narrow, and this pins why.
///
/// A bunyip-provisioned user has no `password_hash` at all
/// (`upsert_user_from_oidc` writes none), so the password branch already
/// refused them before PMS-905 - with a 401, at `service.rs`'s
/// `ok_or(Unauthorized)`. The accounts the new 403 closes are the ones that
/// carry a local hash: the bootstrap admin and anything predating a switch to
/// SaaS. Worth pinning because it is the reason this change is small, and the
/// reason the break-glass above is narrow rather than a hole.
#[sqlx::test]
async fn a_federated_user_has_no_local_password_to_refuse_in_the_first_place(pool: PgPool) {
    let email = "federated@example.test";
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO users (id, tenant_id, email, first_name, last_name, role, status)
        VALUES ($1, $2, $3, 'Fed', 'User', 'technician', 'active')
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(email)
    .execute(&pool)
    .await
    .expect("seed passwordless user");

    // Even in the posture that leaves local auth fully open.
    let got = service(&pool, DeploymentMode::Saas, false)
        .login(&login_request(email), None, None)
        .await;
    assert!(
        matches!(got, Err(AppError::Unauthorized)),
        "a user with no password hash is refused by the credential check itself, not by \
         the deployment gate, got {got:?}"
    );
}
