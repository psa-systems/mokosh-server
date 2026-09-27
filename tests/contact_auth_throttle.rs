//! PMS-1297: the contact plane's unauthenticated credential routes are
//! throttled, and the budget is spent per contact rather than per request.
//!
//! PMS-1343 removed the self-service reset, so the two cases about that
//! endpoint went with it and the shared-budget case became a single-door one;
//! the note at the foot of this file says where each property lives now.

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_contact(pool: &PgPool) -> common::PortalContact {
    let company = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Acme Co')")
        .bind(company)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    common::seed_portal_contact(pool, company, "user@example.com", &[]).await
}

async fn post(app: &common::TestApp, path: &str, body: serde_json::Value) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .json(&body)
        .send()
        .await
        .expect("send")
}

/// The redemption budget is per CONTACT, so guessing at a link is throttled
/// however many requests it is spread over.
///
/// PMS-1343: this used to spend the quota across `set-password` and
/// `reset-password` together, to prove the two shared one budget rather than
/// handing an attacker double. `reset-password` is gone with the self-service
/// reset, so the budget has one door now; what still matters, and is what the
/// test was really about, is that the door is keyed on the contact in the
/// token rather than on the request.
#[mokosh_test]
async fn the_redemption_budget_is_spent_per_contact(pool: PgPool) {
    let contact = seed_contact(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = format!("{}.no-such-secret", contact.id);
    let body = serde_json::json!({ "token": token, "password": "Xy9#pQ4v!Lm2wRt7" });

    // Account quota is 3 per minute.
    for _ in 0..3 {
        let r = post(&app, "/api/v1/contact/auth/set-password", body.clone()).await;
        assert_ne!(r.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    }
    let r = post(&app, "/api/v1/contact/auth/set-password", body).await;
    assert_eq!(r.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
}

// PMS-1343: two cases went with the endpoints they drove.
//
// `forgot_password_spends_quota_for_known_and_unknown_email` pinned that the
// forgot-password budget was spent whether or not the address matched, so the
// throttle could not be used as an enumeration oracle. Nothing on the contact
// plane takes an email and answers whether it is known any more.
//
// `a_second_reset_token_invalidates_the_first` pinned PMS-1297: a newly minted
// link superseded the outstanding ones. That property did not go with it - the
// MSP's `POST /contacts/{id}/resend-portal-invite` deletes unused tokens
// before minting - and it is pinned in `tests/msp_portal_password_reset.rs`,
// which is where the reset now lives.
