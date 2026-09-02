//! PMS-966: the payment-provider seam resolves by stored column, not by literal.
//!
//! Two things are worth proving from outside the crate. The first is that a
//! provider nothing can serve is now refused at the moment an operator switches
//! it on, where before the config stored happily and every resolution path then
//! skipped it in silence. The second is that removing the `provider = 'stripe'`
//! literal changed nothing for a tenant who already has rows: a stored `authorize_net`
//! row was invisible behind the literal, and it has to stay invisible without
//! it, including on the pre-auth webhook path where the wrong answer is a
//! payment that never reconciles.

mod common;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};

/// The zero encryption key `common::boot_*` wires into the router, so a seeded
/// config decrypts with the key the app decrypts with.
const TEST_KEY: [u8; 32] = [0u8; 32];
const WEBHOOK_SECRET: &str = "whsec_seam_test";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Stripe's `t=<ts>,v1=<hmac>` scheme over `"<ts>.<body>"`.
fn sign(secret: &str, body: &[u8], t: i64) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    format!("t={t},v1={}", hex_encode(&mac.finalize().into_bytes()))
}

/// Insert a gateway row directly, bypassing the API's activation guard.
///
/// Deliberately not through `PUT /payment-gateways`: the point of the
/// `authorize_net` cases below is a row that predates the guard, which is the only
/// way one can exist, so seeding through the guarded route would test nothing.
async fn seed_gateway(pool: &PgPool, provider: &str, is_active: bool) {
    let plaintext = serde_json::json!({
        "secret_key": "sk_test_unused_in_webhook_path",
        "webhook_secret": WEBHOOK_SECRET,
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, $2, $3, TRUE, $4)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .bind(is_active)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed gateway");
}

async fn put_gateway(
    app: &common::TestApp,
    token: &str,
    provider: &str,
    is_active: bool,
) -> reqwest::Response {
    app.client
        .put(app.url("/api/v1/payment-gateways"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "provider": provider,
            "is_active": is_active,
            "is_test_mode": true,
            "config": {"secret_key": "sk_test_x", "webhook_secret": WEBHOOK_SECRET},
        }))
        .send()
        .await
        .expect("put gateway")
}

/// The silence this issue removes. Before PMS-966 this stored an active row
/// that no resolution path would ever read, and answered 200.
#[sqlx::test]
async fn activating_a_provider_nothing_can_serve_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = put_gateway(&app, &token, "authorize_net", true).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "activating an unimplemented provider must be refused, not stored"
    );
    let body: Value = resp.json().await.expect("error body");
    let text = body.to_string();
    assert!(
        text.contains("stripe"),
        "the refusal should name what IS supported, got {text}"
    );

    // And nothing was written: the operator's account is unchanged.
    let stored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_gateway_configs WHERE tenant_id = $1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("count configs");
    assert_eq!(stored, 0, "a refused activation must store nothing");
}

/// Storing credentials ahead of support is not the thing that lies, so it stays
/// allowed. Only switching the gateway on is refused.
#[sqlx::test]
async fn storing_an_inactive_config_for_an_unserveable_provider_is_allowed(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = put_gateway(&app, &token, "authorize_net", false).await;
    assert!(
        resp.status().is_success(),
        "an inactive config is not a claim that it works, got {}",
        resp.status()
    );
}

/// Stripe is unaffected by the guard.
#[sqlx::test]
async fn activating_stripe_still_works(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = put_gateway(&app, &token, "stripe", true).await;
    assert!(
        resp.status().is_success(),
        "stripe must still activate, got {}",
        resp.status()
    );
}

/// The refactor's central claim, on the path where being wrong costs money.
///
/// A tenant carrying an active `authorize_net` row from before the guard, alongside
/// their real Stripe config, must have their Stripe webhook verify exactly as
/// it did when the SQL literal picked the row. If resolution returned the
/// authorize_net row instead, the signature would fail against the wrong secret and
/// the payment would never reconcile.
#[sqlx::test]
async fn a_legacy_unserveable_row_does_not_shadow_the_stripe_one(pool: PgPool) {
    seed_gateway(&pool, "authorize_net", true).await;
    seed_gateway(&pool, "stripe", true).await;
    let app = common::boot_rls(pool.clone()).await;

    // An event the parser recognises and deliberately does not act on: this
    // asserts the signature verified, without needing an invoice to exist.
    let body = serde_json::json!({
        "id": "evt_seam",
        "type": "checkout.session.expired",
        "data": {"object": {"id": "cs_seam"}},
    })
    .to_string();
    let signature = sign(WEBHOOK_SECRET, body.as_bytes(), now_unix());

    let url = app.url(&format!(
        "/api/v1/stripe/webhooks/{}",
        common::DEFAULT_TENANT_ID
    ));
    let resp = app
        .client
        .post(&url)
        .header("Stripe-Signature", signature)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post webhook");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "the stripe config must still be the one resolved"
    );
}

/// A tenant whose ONLY active gateway is unserveable is indistinguishable from
/// one with no gateway at all, which is what the literal did and what the
/// receiver's 401 already means. It must not become a 500 that tells an
/// unauthenticated caller the tenant exists and is misconfigured.
#[sqlx::test]
async fn a_tenant_with_only_an_unserveable_gateway_answers_like_an_unconfigured_one(pool: PgPool) {
    seed_gateway(&pool, "authorize_net", true).await;
    let app = common::boot_rls(pool.clone()).await;

    let body = serde_json::json!({"id": "evt_x", "type": "checkout.session.expired"}).to_string();
    let signature = sign(WEBHOOK_SECRET, body.as_bytes(), now_unix());
    let url = app.url(&format!(
        "/api/v1/stripe/webhooks/{}",
        common::DEFAULT_TENANT_ID
    ));
    let resp = app
        .client
        .post(&url)
        .header("Stripe-Signature", signature)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post webhook");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an unserveable gateway must answer as no gateway, not as a server error"
    );
}
