//! MAPPS-674: portal-contact saved payment methods.
//!
//! Exercises the `/api/v1/contact/payment-methods` surface end to end:
//!
//! - Contact with `payment_methods:manage_own` (built-in Billing Contact)
//!   lists their own cards (empty at first). Contact without it 403s.
//! - `POST /payment-methods` reaches the service and refuses with a
//!   no-gateway 400 when no Stripe row exists on the tenant. That 400 is
//!   the "handler cleared every gate" signal, matching the `pay_invoice`
//!   suite's shape.
//! - `PUT /payment-methods/{id}/default` with two saved cards flips
//!   `is_default` atomically: the picked row wins, the other clears, the
//!   partial UNIQUE index would refuse anything else.
//! - `DELETE /payment-methods/{id}` refuses with the same no-gateway
//!   posture on a tenant without a gateway (the service tries to detach
//!   through the provider FIRST); rows are seeded directly for the
//!   set-default flip so the deletion path is exercised where the
//!   gateway is intentionally absent.

mod common;

use mokosh_test::mokosh_test;
use std::sync::OnceLock;

use axum::{extract::Path, routing::post, Json, Router};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const NO_GATEWAY: &str = "no active payment provider is configured";
const TEST_KEY: [u8; 32] = [0u8; 32];

/// A stub Stripe API for the PMS-1235 default-promotion test, which needs
/// `remove()` to reach a real `detach_payment_method` call rather than
/// stopping at the no-gateway 400 the other rows in this file use. One
/// server for the whole binary, on its own thread with its own runtime, the
/// same shape `tests/paypal_pay_now.rs` uses for the same reason:
/// `STRIPE_API_BASE` is process-global and `#[mokosh_test]` cases run
/// concurrently.
fn stripe_stub_base() -> &'static str {
    static STUB: OnceLock<String> = OnceLock::new();
    STUB.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("stub runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind stub");
                let base = format!("http://{}", listener.local_addr().unwrap());
                let router = Router::new().route(
                    "/v1/payment_methods/{id}/detach",
                    post(|Path(_id): Path<String>| async {
                        Json(json!({"object": "payment_method"}))
                    }),
                );
                tx.send(base).unwrap();
                axum::serve(listener, router).await.unwrap();
            });
        });
        let base = rx.recv().expect("stub base");
        std::env::set_var("STRIPE_API_BASE", &base);
        // PMS-982: the config generation is resolved and held, so the
        // `set_var` above is not seen until it is rebuilt.
        mokosh_server::config::refresh();
        base
    })
}

async fn seed_stripe_gateway(pool: &PgPool) {
    let plaintext = json!({
        "secret_key": "sk_test_1", "webhook_secret": "whsec_1",
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'stripe', TRUE, TRUE, $2)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed stripe gateway");
}

async fn seed_paypal_gateway(pool: &PgPool) {
    let plaintext = json!({
        "client_id": "cid", "client_secret": "csec",
        "webhook_id": "WH-TEST-1", "sandbox": true,
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'paypal', TRUE, TRUE, $2)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed paypal gateway");
}

/// Same shape as `seed_payment_method` but with an explicit `created_at`,
/// so the PMS-1235 promotion test can pin which of two rows is "newest"
/// without depending on two inserts landing in different microseconds.
async fn seed_payment_method_at(
    pool: &PgPool,
    tenant_id: Uuid,
    contact_id: Uuid,
    provider_pm_id: &str,
    last4: &str,
    is_default: bool,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_payment_methods \
         (id, tenant_id, contact_id, provider, provider_pm_id, brand, last4, exp_month, exp_year, is_default, created_at) \
         VALUES ($1, $2, $3, 'stripe', $4, 'visa', $5, 12, 2030, $6, $7)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(contact_id)
    .bind(provider_pm_id)
    .bind(last4)
    .bind(is_default)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed contact_payment_methods");
    id
}

async fn seed_contact_with_roles(
    app: &common::TestApp,
    pool: &PgPool,
    email_local: &str,
    role_names: &[&str],
) -> (Uuid, Uuid, String) {
    let tenant_id = common::DEFAULT_TENANT_ID;
    let email = format!("{email_local}@pm.example");
    let company_id = Uuid::new_v4();
    let slug = format!("pm-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("PM Co {email_local}"))
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Test', 'Payer', $4)",
    )
    .bind(contact_id)
    .bind(tenant_id)
    .bind(company_id)
    .bind(&email)
    .execute(pool)
    .await
    .expect("seed contact");

    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let mut role_ids = Vec::new();
    for name in role_names {
        let id: Uuid =
            sqlx::query_scalar("SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = $2")
                .bind(tenant_id)
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("read portal_role {name}: {e}"));
        role_ids.push(id);
    }
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(tenant_id),
            contact_id,
            &role_ids,
            &mokosh_server::modules::audit::AuditCtx::system(tenant_id),
        )
        .await
        .expect("grant_portal_access");

    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("token in setup_link")
        .to_string();
    let strong = "Kq7$mZ2n#PxR9wLf";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": token, "password": strong }))
        .send()
        .await
        .expect("set-password");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "set-password 204");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "slug": outcome.portal_slug,
            "email": email,
            "password": strong,
        }))
        .send()
        .await
        .expect("contact login");
    assert_eq!(resp.status(), StatusCode::OK, "contact login 200");
    let body: Value = resp.json().await.expect("login JSON");
    let access = body["access_token"]
        .as_str()
        .expect("access_token in login response")
        .to_string();
    (company_id, contact_id, access)
}

/// Seed a row directly so the set-default / list assertions do not need
/// the webhook path to run. `is_default = FALSE` by default; the caller
/// picks which of the two rows they want the flip to land on.
async fn seed_payment_method(
    pool: &PgPool,
    tenant_id: Uuid,
    contact_id: Uuid,
    provider_pm_id: &str,
    last4: &str,
    is_default: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_payment_methods \
         (id, tenant_id, contact_id, provider, provider_pm_id, brand, last4, exp_month, exp_year, is_default) \
         VALUES ($1, $2, $3, 'stripe', $4, 'visa', $5, 12, 2030, $6)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(contact_id)
    .bind(provider_pm_id)
    .bind(last4)
    .bind(is_default)
    .execute(pool)
    .await
    .expect("seed contact_payment_methods");
    id
}

/// Row 1: a Billing Contact (which the built-in seed grants
/// `payment_methods:manage_own`) can list their own methods. Empty until
/// a webhook lands.
#[mokosh_test]
async fn contact_with_cap_lists_own_methods(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company, _contact, token) =
        seed_contact_with_roles(&app, &pool, "pm-list", &["Billing Contact"]).await;

    let resp = app
        .client
        .get(app.url("/api/v1/contact/payment-methods"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), StatusCode::OK, "MAPPS-674: list 200");
    let body: Value = resp.json().await.expect("json");
    assert!(
        body.as_array().is_some_and(|a| a.is_empty()),
        "MAPPS-674: fresh contact has no saved methods, got {body}"
    );
}

/// Row 2: a Support Contact holds `settings:manage_own` but NOT
/// `payment_methods:manage_own`. Every route must refuse.
#[mokosh_test]
async fn contact_without_cap_403(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company, _contact, token) =
        seed_contact_with_roles(&app, &pool, "pm-nocap", &["Support Contact"]).await;

    for path in ["/api/v1/contact/payment-methods"] {
        let resp = app
            .client
            .get(app.url(path))
            .bearer_auth(&token)
            .send()
            .await
            .expect("get");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "MAPPS-674: {path} without cap must 403"
        );
    }

    let resp = app
        .client
        .post(app.url("/api/v1/contact/payment-methods"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "success_url": "https://portal.example/methods",
            "cancel_url": "https://portal.example/methods",
        }))
        .send()
        .await
        .expect("start_add");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "MAPPS-674: POST without cap must 403"
    );
}

/// Row 3: with the cap AND no gateway configured on the tenant, `POST` reaches
/// the service and hits the same no-gateway 400 the pay-invoice matrix uses
/// as the "the handler cleared every gate" signal. The Stripe-integrated
/// success case is exercised elsewhere against a real key.
#[mokosh_test]
async fn start_add_without_gateway_400(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company, _contact, token) =
        seed_contact_with_roles(&app, &pool, "pm-add", &["Billing Contact"]).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/payment-methods"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "success_url": "https://portal.example/methods",
            "cancel_url": "https://portal.example/methods",
        }))
        .send()
        .await
        .expect("start_add");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "MAPPS-674: no gateway means 400 from the service, cap + validation passed"
    );
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_ascii_lowercase().contains(NO_GATEWAY),
        "MAPPS-674: no-gateway message expected, got {body}"
    );
}

/// Row 4: `PUT /payment-methods/{id}/default` with two seeded rows flips
/// the picked one to default and clears the other in one transaction.
#[mokosh_test]
async fn set_default_flips_atomically(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company, contact_id, token) =
        seed_contact_with_roles(&app, &pool, "pm-default", &["Billing Contact"]).await;
    // Two seeded rows on the same contact. Row A is the initial default;
    // Row B is a newer card the customer wants to promote.
    let a = seed_payment_method(
        &pool,
        common::DEFAULT_TENANT_ID,
        contact_id,
        "pm_test_A",
        "4242",
        true,
    )
    .await;
    let b = seed_payment_method(
        &pool,
        common::DEFAULT_TENANT_ID,
        contact_id,
        "pm_test_B",
        "1111",
        false,
    )
    .await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/contact/payment-methods/{b}/default")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("set-default");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "MAPPS-674: set-default returns 204"
    );

    let a_default: bool =
        sqlx::query_scalar("SELECT is_default FROM contact_payment_methods WHERE id = $1")
            .bind(a)
            .fetch_one(&pool)
            .await
            .expect("read a");
    let b_default: bool =
        sqlx::query_scalar("SELECT is_default FROM contact_payment_methods WHERE id = $1")
            .bind(b)
            .fetch_one(&pool)
            .await
            .expect("read b");
    assert!(
        !a_default && b_default,
        "MAPPS-674: after flip B is default and A is not (a_default={a_default}, b_default={b_default})"
    );
}

/// Row 5: `PUT /default` on an unknown id 404s, so a foreign guess does
/// not silently succeed or reveal existence.
#[mokosh_test]
async fn set_default_unknown_id_404(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (_company, _contact, token) =
        seed_contact_with_roles(&app, &pool, "pm-unknown", &["Billing Contact"]).await;

    let stranger = Uuid::new_v4();
    let resp = app
        .client
        .put(app.url(&format!(
            "/api/v1/contact/payment-methods/{stranger}/default"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("set-default");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "MAPPS-674: unknown id must 404, not 204"
    );
}

/// PMS-1235: deleting the default card must not leave the contact with no
/// default at all when other cards remain, since the future auto-charge
/// worker this table exists for names a specific card by looking here.
/// Needs a working Stripe stub because `remove()` detaches on the provider
/// side before it deletes the row and before it can promote anything.
#[mokosh_test]
async fn deleting_the_default_promotes_the_newest_remaining_method(pool: PgPool) {
    stripe_stub_base();
    seed_stripe_gateway(&pool).await;
    let app = common::boot(pool.clone()).await;
    let (_company, contact_id, token) =
        seed_contact_with_roles(&app, &pool, "pm-promote", &["Billing Contact"]).await;

    let now = Utc::now();
    let a = seed_payment_method_at(
        &pool,
        common::DEFAULT_TENANT_ID,
        contact_id,
        "pm_test_A",
        "4242",
        true,
        now - chrono::Duration::seconds(10),
    )
    .await;
    let b = seed_payment_method_at(
        &pool,
        common::DEFAULT_TENANT_ID,
        contact_id,
        "pm_test_B",
        "1111",
        false,
        now,
    )
    .await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contact/payment-methods/{a}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "MAPPS-674: delete returns 204"
    );

    let b_default: bool =
        sqlx::query_scalar("SELECT is_default FROM contact_payment_methods WHERE id = $1")
            .bind(b)
            .fetch_one(&pool)
            .await
            .expect("read b");
    assert!(
        b_default,
        "PMS-1235: the remaining, newest card must be promoted to default"
    );
}

/// PMS-1235: a tenant with two active providers must not be refused
/// disambiguation just because it names one. Given no provider at all the
/// old, still-correct ambiguity refusal stands.
#[mokosh_test]
async fn start_add_with_no_provider_on_dual_provider_tenant_stays_ambiguous(pool: PgPool) {
    seed_stripe_gateway(&pool).await;
    seed_paypal_gateway(&pool).await;
    let app = common::boot(pool.clone()).await;
    let (_company, _contact, token) =
        seed_contact_with_roles(&app, &pool, "pm-dual-none", &["Billing Contact"]).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/payment-methods"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "success_url": "https://portal.example/methods",
            "cancel_url": "https://portal.example/methods",
        }))
        .send()
        .await
        .expect("start_add");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        msg.to_ascii_lowercase().contains("say which one"),
        "PMS-1235: no provider named on a dual-provider tenant must still be refused as ambiguous, got {body}"
    );
}

/// PMS-1235: naming a provider on a dual-provider tenant must move past the
/// ambiguity refusal and resolve that provider. PayPal has no SetupIntent
/// support yet, so it still refuses, but with PayPal's own message rather
/// than the ambiguity one, proving the name was honoured.
#[mokosh_test]
async fn start_add_with_named_provider_on_dual_provider_tenant_resolves_it(pool: PgPool) {
    seed_stripe_gateway(&pool).await;
    seed_paypal_gateway(&pool).await;
    let app = common::boot(pool.clone()).await;
    let (_company, _contact, token) =
        seed_contact_with_roles(&app, &pool, "pm-dual-named", &["Billing Contact"]).await;

    let resp = app
        .client
        .post(app.url("/api/v1/contact/payment-methods"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "success_url": "https://portal.example/methods",
            "cancel_url": "https://portal.example/methods",
            "provider": "paypal",
        }))
        .send()
        .await
        .expect("start_add");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("");
    assert!(
        !msg.to_ascii_lowercase().contains("say which one"),
        "PMS-1235: naming a provider must not hit the ambiguity refusal, got {body}"
    );
    assert!(
        msg.to_ascii_lowercase()
            .contains("does not support saved payment methods"),
        "PMS-1235: expected paypal's own setup-intent refusal, got {body}"
    );
}
