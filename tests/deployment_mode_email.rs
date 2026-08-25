//! PMS-904: mail that exists only to service a LOCAL platform credential does
//! not send when platform identity is federated to Bunyip SSO.
//!
//! `MOKOSH_DEPLOYMENT_MODE=saas` says a `users` row's password is not the
//! credential anybody signs in with. A password-reset link then sets a password
//! that opens nothing, and a "welcome, set your password" mail names a step
//! that does not exist in that deployment. Both are worse than silence: they
//! read as though they have solved the recipient's problem.
//!
//! What these tests pin, in both directions, is that the suppression is
//! conditioned on the mode and nothing else. Every assertion below is run
//! twice, once per mode, from the same fixture, so a gate that suppressed
//! unconditionally (or one that never fired) fails rather than passing half the
//! time.
//!
//! Two sites named by the issue are covered elsewhere, for reasons that are
//! properties of those sites rather than gaps here:
//!
//! - The new-login-location alert cannot fire in this suite at all.
//!   `check_login_location` returns immediately when no IP2Location DB is
//!   configured, and the integration harness configures none, so a behavioural
//!   test would assert the absence of an email that was never going to be sent
//!   in either mode. Its gate is covered by the unit tests on
//!   `AuthService::sends_local_account_email` and `DeploymentMode`.
//! - The login-approval code is deliberately NOT gated; see the comment at
//!   `issue_login_approval` and PMS-905. `tests/login_approval.rs` continues to
//!   pin that it sends.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::AuthService;
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::utils::deployment::DeploymentMode;
use mokosh_server::Database;
use mokosh_types::auth::CreateUserRequest;

/// An `AuthService` with the notifications dispatcher wired, in the given mode.
///
/// `with_dispatcher` rather than `with_mailer`: the two gated sites here queue
/// through `notification_templates` and never touch the `Mailer` directly, so a
/// fixture without a dispatcher would take the `None` branch and queue nothing
/// in either mode - a test that passes for the wrong reason.
fn service(pool: &PgPool, mode: DeploymentMode) -> AuthService {
    let db = Database::from_pool(pool.clone());
    AuthService::with_dispatcher(
        db.clone(),
        "test-jwt-secret-please-change".to_string(),
        std::sync::Arc::new(mokosh_server::utils::email::LogMailer),
        "http://localhost:4301".to_string(),
        NotificationsService::with_encryption_key(db, [0u8; 32]),
    )
    .with_deployment_mode(mode)
}

/// How many email rows are queued for `recipient`. The dispatcher writes one
/// per rule match; the worker drains them later, so this counts what was
/// dispatched without needing the worker to run.
async fn queued_for(pool: &PgPool, recipient: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM notifications WHERE channel_type = 'email' AND recipient = $1",
    )
    .bind(recipient)
    .fetch_one(pool)
    .await
    .expect("count queued notifications")
}

/// A `create_user` request that asks for the welcome mail. Only the fields the
/// gate depends on matter; the rest take their neutral values.
fn new_user(email: &str) -> CreateUserRequest {
    CreateUserRequest {
        email: email.to_string(),
        first_name: "New".to_string(),
        last_name: "Person".to_string(),
        phone: None,
        mobile: None,
        title: None,
        role: mokosh_types::auth::UserRole::Technician,
        timezone: None,
        date_format_string: None,
        theme_base_mode: None,
        theme_accent_id: None,
        send_welcome_email: true,
    }
}

/// Seed a platform user with a password hash, the shape a local-auth
/// deployment has and a federated one does not need.
async fn seed_user(pool: &PgPool, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = mokosh_server::utils::crypto::hash_password("local-password-123")
        .expect("hash test password");
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

/// AC1: `request_password_reset` still answers `Ok(())` in both modes - the
/// endpoint's contract is that it never reveals whether an address has an
/// account - but queues nothing in `saas`.
#[sqlx::test]
async fn password_reset_queues_in_self_hosted_and_is_suppressed_in_saas(pool: PgPool) {
    let self_hosted = "reset-selfhosted@example.test";
    let saas = "reset-saas@example.test";
    seed_user(&pool, self_hosted).await;
    seed_user(&pool, saas).await;

    service(&pool, DeploymentMode::SelfHosted)
        .request_password_reset(Some(common::DEFAULT_TENANT_ID), self_hosted)
        .await
        .expect("self-hosted reset returns Ok");
    assert_eq!(
        queued_for(&pool, self_hosted).await,
        1,
        "a self-hosted deployment owns the credential, so it must still send the reset link"
    );

    service(&pool, DeploymentMode::Saas)
        .request_password_reset(Some(common::DEFAULT_TENANT_ID), saas)
        .await
        .expect("saas reset still returns Ok, exactly as an unknown address does");
    assert_eq!(
        queued_for(&pool, saas).await,
        0,
        "the credential lives in Bunyip, so a mokosh reset link would set a password \
         that signs nobody in"
    );
}

/// The suppression must not become an enumeration oracle. A caller cannot tell
/// a suppressed reset from one for an address with no account, because both
/// return the same `Ok(())` and neither queues anything.
#[sqlx::test]
async fn a_suppressed_reset_is_indistinguishable_from_an_unknown_address(pool: PgPool) {
    let known = "known@example.test";
    seed_user(&pool, known).await;
    let svc = service(&pool, DeploymentMode::Saas);

    let for_known = svc
        .request_password_reset(Some(common::DEFAULT_TENANT_ID), known)
        .await;
    let for_unknown = svc
        .request_password_reset(Some(common::DEFAULT_TENANT_ID), "nobody@example.test")
        .await;

    assert!(for_known.is_ok() && for_unknown.is_ok());
    assert_eq!(queued_for(&pool, known).await, 0);
    assert_eq!(queued_for(&pool, "nobody@example.test").await, 0);
}

/// AC2: `create_user` still creates the account in both modes. Only the mail
/// about the local password is withheld: the `users` row is what scopes the
/// person to this tenant, and a SaaS deployment needs it just as much.
#[sqlx::test]
async fn the_welcome_mail_is_suppressed_in_saas_but_the_account_is_still_created(pool: PgPool) {
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let request = |email: &str| new_user(email);

    let self_hosted = "welcome-selfhosted@example.test";
    let created = service(&pool, DeploymentMode::SelfHosted)
        .create_user(common::DEFAULT_TENANT_ID, &request(self_hosted), &ctx)
        .await
        .expect("self-hosted create_user");
    assert_eq!(created.email, self_hosted);
    assert_eq!(
        queued_for(&pool, self_hosted).await,
        1,
        "a self-hosted deployment has a password for the welcome mail to set"
    );

    let saas = "welcome-saas@example.test";
    let created = service(&pool, DeploymentMode::Saas)
        .create_user(common::DEFAULT_TENANT_ID, &request(saas), &ctx)
        .await
        .expect("saas create_user still creates the account");
    assert_eq!(
        created.email, saas,
        "the account row is what scopes this person to the tenant; suppressing the mail \
         must not suppress the account"
    );
    assert_eq!(
        queued_for(&pool, saas).await,
        0,
        "there is no mokosh password to set, so the welcome mail names a step that does \
         not exist in this deployment"
    );
}

/// Neither gated site mints a `password_reset_tokens` row in `saas`.
///
/// Both sites write one, and in both cases the suppressed mail is its ONLY
/// carrier: the plaintext `{id}.{secret}` exists in memory for the length of
/// the call and nothing else ever emits it. Minting one anyway would leave a
/// live credential-bearing row that no recipient can redeem and no code path
/// retires before its TTL. This is also why each gate sits above its token
/// write rather than just above the dispatch.
#[sqlx::test]
async fn saas_mints_no_token_whose_only_carrier_was_suppressed(pool: PgPool) {
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);
    let saas = service(&pool, DeploymentMode::Saas);

    let reset_user = seed_user(&pool, "token-reset-saas@example.test").await;
    saas.request_password_reset(
        Some(common::DEFAULT_TENANT_ID),
        "token-reset-saas@example.test",
    )
    .await
    .expect("saas reset");

    let created = saas
        .create_user(
            common::DEFAULT_TENANT_ID,
            &new_user("token-welcome-saas@example.test"),
            &ctx,
        )
        .await
        .expect("saas create_user");

    for (user_id, site) in [(reset_user, "password reset"), (created.id, "welcome")] {
        let tokens: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("count tokens");
        assert_eq!(
            tokens, 0,
            "{site}: the suppressed mail was this token's only carrier, so none may be left behind"
        );
    }
}

/// AC4: business, portal and diagnostic mail is not identity mail, and must be
/// untouched by the mode in both directions.
///
/// The regression worth guarding against is a gate placed one level too high.
/// Put the check in `NotificationsService::dispatch`, in the dispatcher worker,
/// or behind the `Mailer` trait, and a SaaS tenant silently stops sending its
/// customers quotes and invoices - a far larger failure than the one PMS-904
/// set out to fix, and one nothing would report.
///
/// A source scan rather than fifteen behavioural tests, because what is being
/// pinned is exactly a negative about WHERE the knowledge lives: that no module
/// other than the auth service and the startup wiring can even ask which mode
/// this is. Each of those fifteen dispatch sites already has its own suite; a
/// second copy here would pin their behaviour, not this boundary.
#[test]
fn only_the_auth_service_and_the_startup_wiring_know_the_deployment_mode() {
    let mut offenders: Vec<String> = Vec::new();
    let permitted = [
        // Defines the vocabulary.
        "src/utils/deployment.rs",
        // Owns the three gated sites.
        "src/modules/auth/service.rs",
        // Startup wiring: reads the env var and threads it in.
        "src/main.rs",
        "src/api/router.rs",
        // Re-export only.
        "src/utils/mod.rs",
    ];

    let mut stack = vec![std::path::PathBuf::from("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = path.to_string_lossy().replace('\\', "/");
            if permitted.contains(&rel.as_str()) {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read source");
            if src.contains("DeploymentMode") || src.contains("MOKOSH_DEPLOYMENT_MODE") {
                offenders.push(rel);
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "PMS-904 gates mail for the LOCAL platform credential and nothing else. A module \
         that consults the deployment mode is either gating business, portal or diagnostic \
         mail (which must send in both modes), or duplicating a decision that belongs to \
         AuthService. Found in: {offenders:?}"
    );
}
