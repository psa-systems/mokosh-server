//! PMS-658: integration tests for the suspicious-login notify-and-approve gate.
//!
//! Exercises the device signal, which needs no IP2Location DB: a login from a
//! new device is flagged (`approval_required`, tokens withheld), the emailed
//! code completes it, and the device is then remembered. Also pins the
//! wrong-code rejection and the baseline (first-device) pass-through.

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sqlx::PgPool;

use mokosh_server::modules::auth::AuthService;
use mokosh_server::utils::email::Mailer;
use mokosh_server::utils::error::AppResult;
use mokosh_server::Database;
use mokosh_types::auth::LoginRequest;

/// Mailer that captures the most recent login-approval code so the test can
/// complete the challenge. Every other mail is dropped.
#[derive(Default)]
struct CapturingMailer {
    last_code: Mutex<Option<String>>,
}

#[async_trait]
impl Mailer for CapturingMailer {
    async fn send_multipart(
        &self,
        _to: &str,
        _subject: &str,
        _text: &str,
        _html: Option<&str>,
    ) -> AppResult<()> {
        Ok(())
    }
    async fn send_login_approval_code(
        &self,
        _to: &str,
        code: &str,
        _country: Option<&str>,
        _ip: Option<&str>,
        _when: &str,
        _user_agent: &str,
    ) -> AppResult<()> {
        *self.last_code.lock().unwrap() = Some(code.to_string());
        Ok(())
    }
}

fn login_request(
    email: &str,
    password: &str,
    device_id: &str,
    approval_code: Option<&str>,
) -> LoginRequest {
    LoginRequest {
        email: email.to_string(),
        password: password.to_string(),
        remember_me: false,
        mfa_code: None,
        recovery_code: None,
        approval_code: approval_code.map(str::to_string),
        device_id: Some(device_id.to_string()),
        tenant_id: Some(common::DEFAULT_TENANT_ID),
        tenant_slug: None,
    }
}

fn service(pool: PgPool, mailer: Arc<CapturingMailer>) -> AuthService {
    AuthService::with_mailer(
        Database::from_pool(pool),
        "test-jwt-secret-please-change".to_string(),
        vec![],
        mailer,
        "http://localhost:4301".to_string(),
    )
    .with_login_approval(true)
}

const IP: &str = "203.0.113.7";
const UA: &str = "test-agent/1.0";

/// The service emails the approval code on a detached `tokio::spawn`, so it may
/// not have landed the instant `login()` returns. Poll the capturing mailer for
/// up to ~1s.
async fn wait_for_code(mailer: &CapturingMailer) -> String {
    for _ in 0..100 {
        if let Some(code) = mailer.last_code.lock().unwrap().clone() {
            return code;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("approval code was not emailed within 1s");
}

#[sqlx::test]
async fn new_device_login_requires_approval_then_succeeds(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let mailer = Arc::new(CapturingMailer::default());
    let svc = service(pool.clone(), mailer.clone());

    // First login on device "A": the user has no known device yet, so this is
    // baseline (recorded, not flagged) and issues tokens.
    let first = svc
        .login(
            &login_request(&email, &password, "device-A", None),
            Some(IP.into()),
            Some(UA.into()),
        )
        .await
        .expect("first login");
    assert!(
        !first.approval_required,
        "the first-ever device is baseline, not flagged"
    );
    assert!(!first.access_token.is_empty(), "first login issues tokens");

    // Second login on a NEW device "B": flagged. Tokens withheld, code emailed.
    let flagged = svc
        .login(
            &login_request(&email, &password, "device-B", None),
            Some(IP.into()),
            Some(UA.into()),
        )
        .await
        .expect("flagged login returns Ok carrying approval_required");
    assert!(
        flagged.approval_required,
        "a new device is flagged for approval"
    );
    assert!(
        flagged.access_token.is_empty(),
        "no tokens are issued while approval is pending"
    );
    assert!(
        flagged.user.is_none(),
        "no user profile leaks while approval is pending"
    );

    let code = wait_for_code(&mailer).await;

    // A wrong code is rejected.
    let wrong = svc
        .login(
            &login_request(&email, &password, "device-B", Some("000000")),
            Some(IP.into()),
            Some(UA.into()),
        )
        .await;
    assert!(wrong.is_err(), "a wrong approval code is rejected");

    // The correct code completes the login and records device B.
    let approved = svc
        .login(
            &login_request(&email, &password, "device-B", Some(&code)),
            Some(IP.into()),
            Some(UA.into()),
        )
        .await
        .expect("approved login");
    assert!(!approved.approval_required);
    assert!(
        !approved.access_token.is_empty(),
        "the approved login issues tokens"
    );

    // Device B is now known: a further login on it is not re-flagged.
    let repeat = svc
        .login(
            &login_request(&email, &password, "device-B", None),
            Some(IP.into()),
            Some(UA.into()),
        )
        .await
        .expect("repeat login on the now-known device");
    assert!(
        !repeat.approval_required,
        "a known device is not re-flagged"
    );
    assert!(!repeat.access_token.is_empty());
}

#[sqlx::test]
async fn gate_disabled_never_flags_a_new_device(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let mailer = Arc::new(CapturingMailer::default());
    // No `.with_login_approval(true)`: the gate is off, matching the default.
    let svc = AuthService::with_mailer(
        Database::from_pool(pool.clone()),
        "test-jwt-secret-please-change".to_string(),
        vec![],
        mailer.clone(),
        "http://localhost:4301".to_string(),
    );

    for device in ["device-A", "device-B", "device-C"] {
        let resp = svc
            .login(
                &login_request(&email, &password, device, None),
                Some(IP.into()),
                Some(UA.into()),
            )
            .await
            .expect("login with the gate disabled");
        assert!(!resp.approval_required, "the disabled gate never flags");
        assert!(!resp.access_token.is_empty(), "tokens issue as normal");
    }
    assert!(
        mailer.last_code.lock().unwrap().is_none(),
        "no approval code is emailed when the gate is disabled"
    );
}
