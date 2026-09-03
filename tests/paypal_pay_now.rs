//! PMS-969: PayPal "Pay Now" reconciliation, end to end, against a stub.
//!
//! Mirrors `tests/pms711_stripe_pay_now.rs` and drives the real
//! `POST /api/v1/paypal/webhooks/{tenant_id}` route through the NOBYPASSRLS
//! app role (`boot_rls`). Two things PayPal does differently from Stripe shape
//! the suite. Verification is a call to PayPal rather than a local HMAC, so the
//! stub is what says SUCCESS or FAILURE, and it decides from the
//! `paypal-transmission-sig` header value alone. And approval does not charge
//! the buyer, so there is a case that proves the receiver calls capture and a
//! case that proves the capture-completed event is what records the payment.
//!
//! One stub server per test binary, on its own thread with its own runtime.
//! `PAYPAL_API_BASE` is process-global and `#[sqlx::test]` cases run
//! concurrently, so a stub per case would race on the variable; and a stub
//! spawned on one case's tokio runtime dies when that case finishes, which is
//! why it gets a thread instead. Every piece of recorded state is keyed by an id
//! the case chose, so the cases cannot see each other's traffic.

mod common;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::{extract::Path, routing::post, Json, Router};
use common::{boot_rls, dec, seed_company, DEFAULT_TENANT_ID};
use rust_decimal::Decimal;
use serde_json::{json, Value};
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0u8; 32];
const WEBHOOK_ID: &str = "WH-TEST-1";
/// The one signature value the stub accepts.
const GOOD_SIG: &str = "good-sig";

/// What the stub saw, keyed by ids the cases choose.
#[derive(Default)]
struct Recorded {
    /// Order ids the receiver asked to capture.
    captures: Vec<String>,
    /// `webhook_event` bodies handed to the verify call, by event id.
    verified_events: HashMap<String, Value>,
}

static RECORDED: Mutex<Option<Recorded>> = Mutex::new(None);
static STUB: OnceLock<String> = OnceLock::new();

fn recorded<T>(f: impl FnOnce(&mut Recorded) -> T) -> T {
    let mut guard = RECORDED.lock().unwrap();
    f(guard.get_or_insert_with(Recorded::default))
}

/// Start the stub once, export `PAYPAL_API_BASE`, and return the base.
fn stub_base() -> &'static str {
    STUB.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("stub runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind stub");
                let base = format!("http://{}", listener.local_addr().unwrap());
                let router = Router::new()
                    .route(
                        "/v1/oauth2/token",
                        post(|| async {
                            Json(json!({"access_token": "stub-token", "expires_in": 3600}))
                        }),
                    )
                    .route(
                        "/v1/notifications/verify-webhook-signature",
                        post(|Json(body): Json<Value>| async move {
                            let event = body["webhook_event"].clone();
                            if let Some(id) = event["id"].as_str() {
                                recorded(|r| {
                                    r.verified_events.insert(id.to_string(), event.clone())
                                });
                            }
                            let ok = body["transmission_sig"].as_str() == Some(GOOD_SIG)
                                && body["webhook_id"].as_str() == Some(WEBHOOK_ID);
                            Json(json!({
                                "verification_status": if ok { "SUCCESS" } else { "FAILURE" }
                            }))
                        }),
                    )
                    .route(
                        "/v2/checkout/orders",
                        post(|| async {
                            Json(json!({
                                "id": "ORDER-STUB",
                                "links": [{"rel": "payer-action", "href": "https://stub/approve"}]
                            }))
                        }),
                    )
                    .route(
                        "/v2/checkout/orders/{id}/capture",
                        post(|Path(id): Path<String>| async move {
                            recorded(|r| r.captures.push(id));
                            (axum::http::StatusCode::CREATED, Json(json!({})))
                        }),
                    );
                tx.send(base).unwrap();
                axum::serve(listener, router).await.unwrap();
            });
        });
        let base = rx.recv().expect("stub base");
        std::env::set_var("PAYPAL_API_BASE", &base);
        base
    })
}

async fn seed_paypal_gateway(pool: &sqlx::PgPool) {
    let plaintext = json!({
        "client_id": "cid", "client_secret": "csec",
        "webhook_id": WEBHOOK_ID, "sandbox": true,
    })
    .to_string();
    let encrypted = mokosh_server::utils::crypto::encrypt(&plaintext, &TEST_KEY).unwrap();
    sqlx::query(
        "INSERT INTO payment_gateway_configs \
         (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
         VALUES ($1, 'paypal', TRUE, TRUE, $2)",
    )
    .bind(DEFAULT_TENANT_ID)
    .bind(encrypted)
    .execute(pool)
    .await
    .expect("seed paypal gateway");
}

async fn seed_sent_invoice(pool: &sqlx::PgPool, company_id: Uuid, total: Decimal) -> Uuid {
    let id = Uuid::new_v4();
    let number = format!("INV-{}", &id.simple().to_string()[..8]);
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, balance_due, currency, sent_at) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE, $5, $5, $5, 'USD', NOW())",
    )
    .bind(id)
    .bind(DEFAULT_TENANT_ID)
    .bind(number)
    .bind(company_id)
    .bind(total)
    .execute(pool)
    .await
    .expect("seed sent invoice");
    id
}

async fn invoice_state(pool: &sqlx::PgPool, id: Uuid) -> (String, Decimal, Decimal) {
    sqlx::query_as("SELECT status, amount_paid, balance_due FROM invoices WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read invoice state")
}

fn capture_completed(event_id: &str, capture_id: &str, invoice_id: Uuid, amount: &str) -> String {
    json!({
        "id": event_id,
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": capture_id,
            "status": "COMPLETED",
            "custom_id": format!("{DEFAULT_TENANT_ID}:{invoice_id}"),
            "amount": {"currency_code": "USD", "value": amount}
        }
    })
    .to_string()
}

/// POST a delivery with PayPal's five headers. `sig` decides what the stub
/// answers on verification.
async fn deliver(app: &common::TestApp, route: &str, body: String, sig: &str) -> reqwest::Response {
    app.client
        .post(app.url(route))
        .header("paypal-transmission-id", "tx-1")
        .header("paypal-transmission-time", "2026-09-02T00:00:00Z")
        .header("paypal-transmission-sig", sig)
        .header("paypal-cert-url", "https://api.paypal.com/cert.pem")
        .header("paypal-auth-algo", "SHA256withRSA")
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post webhook")
}

fn paypal_route() -> String {
    format!("/api/v1/paypal/webhooks/{DEFAULT_TENANT_ID}")
}

#[sqlx::test]
async fn a_completed_capture_marks_the_invoice_paid_and_is_idempotent(pool: sqlx::PgPool) {
    stub_base();
    seed_paypal_gateway(&pool).await;
    let company = seed_company(&pool).await;
    let invoice = seed_sent_invoice(&pool, company, dec("125.00")).await;
    let app = boot_rls(pool.clone()).await;

    let capture = format!("CAP-{}", Uuid::new_v4().simple());
    let body = capture_completed("evt-paid", &capture, invoice, "125.00");

    let resp = deliver(&app, &paypal_route(), body.clone(), GOOD_SIG).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let (status, paid, due) = invoice_state(&pool, invoice).await;
    assert_eq!(status, "paid");
    assert_eq!(paid, dec("125.00"));
    assert_eq!(due, Decimal::ZERO);

    // Redelivery of the same capture records nothing more.
    let resp = deliver(&app, &paypal_route(), body, GOOD_SIG).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payments: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE gateway_transaction_id = $1")
            .bind(&capture)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(payments, 1, "a replayed capture must not double-record");
    assert_eq!(invoice_state(&pool, invoice).await.1, dec("125.00"));
}

#[sqlx::test]
async fn a_refund_walks_the_invoice_back_to_partially_paid(pool: sqlx::PgPool) {
    stub_base();
    seed_paypal_gateway(&pool).await;
    let company = seed_company(&pool).await;
    let invoice = seed_sent_invoice(&pool, company, dec("100.00")).await;
    let app = boot_rls(pool.clone()).await;

    let capture = format!("CAP-{}", Uuid::new_v4().simple());
    deliver(
        &app,
        &paypal_route(),
        capture_completed("evt-p", &capture, invoice, "100.00"),
        GOOD_SIG,
    )
    .await;
    assert_eq!(invoice_state(&pool, invoice).await.0, "paid");

    let refund = json!({
        "id": "evt-refund",
        "event_type": "PAYMENT.CAPTURE.REFUNDED",
        "resource": {
            "id": format!("REF-{}", Uuid::new_v4().simple()),
            "amount": {"currency_code": "USD", "value": "40.00"},
            "links": [{"rel": "up", "href": format!("https://stub/v2/payments/captures/{capture}")}]
        }
    })
    .to_string();
    let resp = deliver(&app, &paypal_route(), refund, GOOD_SIG).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let (status, paid, due) = invoice_state(&pool, invoice).await;
    assert_eq!(status, "partially_paid");
    assert_eq!(paid, dec("60.00"));
    assert_eq!(due, dec("40.00"));
}

#[sqlx::test]
async fn an_unhandled_event_is_a_no_op(pool: sqlx::PgPool) {
    stub_base();
    seed_paypal_gateway(&pool).await;
    let company = seed_company(&pool).await;
    let invoice = seed_sent_invoice(&pool, company, dec("50.00")).await;
    let app = boot_rls(pool.clone()).await;

    let body =
        json!({"id": "evt-sub", "event_type": "BILLING.SUBSCRIPTION.CREATED", "resource": {}})
            .to_string();
    let resp = deliver(&app, &paypal_route(), body, GOOD_SIG).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "ignored, so 200 and no retry"
    );
    assert_eq!(invoice_state(&pool, invoice).await.0, "sent");
}

#[sqlx::test]
async fn a_verification_failure_is_rejected_and_changes_nothing(pool: sqlx::PgPool) {
    stub_base();
    seed_paypal_gateway(&pool).await;
    let company = seed_company(&pool).await;
    let invoice = seed_sent_invoice(&pool, company, dec("75.00")).await;
    let app = boot_rls(pool.clone()).await;

    let body = capture_completed("evt-bad", "CAP-BAD", invoice, "75.00");
    let resp = deliver(&app, &paypal_route(), body, "forged").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let (status, paid, _) = invoice_state(&pool, invoice).await;
    assert_eq!(status, "sent");
    assert_eq!(paid, Decimal::ZERO);
}

/// Approval does not move money. The receiver must call capture, and must
/// write nothing itself: the capture-completed delivery is what records the
/// payment, and that is covered above.
#[sqlx::test]
async fn an_approved_order_is_captured(pool: sqlx::PgPool) {
    stub_base();
    seed_paypal_gateway(&pool).await;
    let company = seed_company(&pool).await;
    let invoice = seed_sent_invoice(&pool, company, dec("30.00")).await;
    let app = boot_rls(pool.clone()).await;

    let order = format!("ORDER-{}", Uuid::new_v4().simple());
    let body = json!({
        "id": "evt-approved",
        "event_type": "CHECKOUT.ORDER.APPROVED",
        "resource": {
            "id": order,
            "purchase_units": [{"custom_id": format!("{DEFAULT_TENANT_ID}:{invoice}")}]
        }
    })
    .to_string();
    let resp = deliver(&app, &paypal_route(), body, GOOD_SIG).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(
        recorded(|r| r.captures.contains(&order)),
        "the receiver must have asked PayPal to capture the approved order"
    );
    assert_eq!(
        invoice_state(&pool, invoice).await.0,
        "sent",
        "approval alone records no payment"
    );
}

/// The reason `/api/v1/paypal/` is in `RAW_BODY_PATHS`. A zero-width space
/// inside a string is exactly what `sanitize_json_body` strips; if it did so
/// here, the body PayPal is asked to verify would not be the body it sent.
#[sqlx::test]
async fn the_body_reaches_verification_byte_identical(pool: sqlx::PgPool) {
    stub_base();
    seed_paypal_gateway(&pool).await;
    let app = boot_rls(pool.clone()).await;

    let event_id = format!("evt-raw-{}", Uuid::new_v4().simple());
    let summary = "Payment\u{200B}completed";
    let body = json!({"id": event_id, "event_type": "IGNORED.FOR.THIS.TEST",
                      "summary": summary, "resource": {}})
    .to_string();
    assert!(
        body.contains('\u{200B}'),
        "the fixture carries the character"
    );

    let resp = deliver(&app, &paypal_route(), body, GOOD_SIG).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let seen = recorded(|r| r.verified_events.get(&event_id).cloned()).expect("stub saw the event");
    assert_eq!(
        seen["summary"].as_str(),
        Some(summary),
        "the sanitizer must not have touched a signature-verified body"
    );
}

/// A tenant on PayPal receiving a delivery on the Stripe route. The receiver
/// resolves the tenant's active provider, finds it is not the one this route
/// is for, and refuses before any verification runs.
#[sqlx::test]
async fn a_delivery_on_the_wrong_providers_route_is_refused(pool: sqlx::PgPool) {
    stub_base();
    seed_paypal_gateway(&pool).await;
    let app = boot_rls(pool.clone()).await;

    let body = json!({"id": "evt-x", "event_type": "IGNORED", "resource": {}}).to_string();
    let resp = deliver(
        &app,
        &format!("/api/v1/stripe/webhooks/{DEFAULT_TENANT_ID}"),
        body,
        GOOD_SIG,
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// One active gateway per tenant, through the API. Activating PayPal turns
/// Stripe off in the same transaction, so `select_serveable` never sees two.
#[sqlx::test]
async fn activating_paypal_deactivates_stripe(pool: sqlx::PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let put = |provider: &'static str, config: Value| {
        let app = &app;
        let token = token.clone();
        async move {
            app.client
                .put(app.url("/api/v1/payment-gateways"))
                .bearer_auth(token)
                .json(&json!({"provider": provider, "is_active": true,
                              "is_test_mode": true, "config": config}))
                .send()
                .await
                .expect("put gateway")
                .status()
        }
    };
    assert!(put(
        "stripe",
        json!({"secret_key": "sk", "webhook_secret": "wh"})
    )
    .await
    .is_success());
    assert!(put(
        "paypal",
        json!({"client_id": "c", "client_secret": "s", "webhook_id": "w"})
    )
    .await
    .is_success());

    let active: Vec<String> = sqlx::query_scalar(
        "SELECT provider FROM payment_gateway_configs WHERE tenant_id = $1 AND is_active ORDER BY provider",
    )
    .bind(DEFAULT_TENANT_ID)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        active,
        vec!["paypal".to_string()],
        "activating one deactivates the other"
    );
}
