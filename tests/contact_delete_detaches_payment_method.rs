//! PMS-1369: deleting a contact must detach its saved payment methods on
//! the provider side before the `DELETE FROM contacts` that (via the FK's
//! `ON DELETE CASCADE`) removes the local `contact_payment_methods` rows.
//! Without this, the local reference disappears silently while the card
//! stays attached to the provider Customer, matching the migration's own
//! documented removal contract (`migrations/218_contact_payment_methods
//! .sql:16-18`): detach on the provider side first, then delete the row.
//!
//! A stub Stripe API records every `/v1/payment_methods/{id}/detach` call
//! it receives, so the tests assert the mock detach was actually invoked
//! with the row's own `provider_pm_id`, not merely that the row is gone.

mod common;

use std::sync::{Mutex, OnceLock};

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use reqwest::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0u8; 32];

/// Every `provider_pm_id` the stub has seen a detach call for, across every
/// test in this binary. Tests seed a unique id per case and assert on
/// `contains`, never on the full list, so concurrent `#[sqlx::test]` cases
/// sharing the one process-wide stub do not interfere with each other.
fn detach_calls() -> &'static Mutex<Vec<String>> {
    static CALLS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    CALLS.get_or_init(|| Mutex::new(Vec::new()))
}

/// One server for the whole binary, on its own thread with its own runtime:
/// `STRIPE_API_BASE` is process-global and `#[sqlx::test]` cases run
/// concurrently (same shape `tests/portal_payment_methods.rs` and
/// `tests/paypal_pay_now.rs` use for the same reason).
///
/// A `provider_pm_id` beginning with `pm_fail_` is answered with a Stripe
/// error body carrying no `resource_missing` code, so
/// `StripeProvider::detach_payment_method` surfaces it as a real failure -
/// the mock provider's way of simulating a detach the provider refuses.
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
                let router = Router::new()
                    .route("/v1/payment_methods/{id}/detach", post(detach_handler))
                    .with_state(());
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

/// PMS-1381 (F3): every simulated detach's own latency, used by the
/// concurrency test below to tell "ran one after another" from "ran at once"
/// without depending on wall-clock noise beyond this one constant.
const SLOW_DETACH_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

async fn detach_handler(Path(id): Path<String>, State(()): State<()>) -> impl IntoResponse {
    detach_calls().lock().unwrap().push(id.clone());
    if id.starts_with("pm_fail_") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"code": "card_error", "message": "simulated detach failure"}})),
        )
            .into_response();
    }
    if id.starts_with("pm_slow_") {
        tokio::time::sleep(SLOW_DETACH_DELAY).await;
    }
    Json(json!({"object": "payment_method"})).into_response()
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

async fn seed_contact(pool: &PgPool) -> Uuid {
    let contact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, first_name, last_name, email) \
         VALUES ($1, $2, 'Card', 'Holder', $3)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("{contact_id}@pm-delete.example"))
    .execute(pool)
    .await
    .expect("seed contact");
    contact_id
}

async fn seed_payment_method(pool: &PgPool, contact_id: Uuid, provider_pm_id: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_payment_methods \
         (id, tenant_id, contact_id, provider, provider_pm_id, brand, last4, exp_month, exp_year, is_default) \
         VALUES ($1, $2, $3, 'stripe', $4, 'visa', '4242', 12, 2030, TRUE)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .bind(provider_pm_id)
    .execute(pool)
    .await
    .expect("seed contact_payment_methods");
    id
}

/// A contact with a saved card, deleted through the staff route: the mock
/// provider's detach must be called with the row's own `provider_pm_id`
/// BEFORE the contact (and, via the FK cascade, the payment method row)
/// disappears.
#[sqlx::test]
async fn deleting_a_contact_detaches_its_saved_payment_method(pool: PgPool) {
    stripe_stub_base();
    seed_stripe_gateway(&pool).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let contact_id = seed_contact(&pool).await;
    let provider_pm_id = format!("pm_delete_{}", Uuid::new_v4().simple());
    seed_payment_method(&pool, contact_id, &provider_pm_id).await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete contact");
    assert!(
        resp.status().is_success(),
        "PMS-1369: delete should 2xx once the provider detach succeeds, got {}",
        resp.status()
    );

    assert!(
        detach_calls().lock().unwrap().contains(&provider_pm_id),
        "PMS-1369: detach_payment_method must be called with the row's provider_pm_id"
    );

    let contact_count: i64 = sqlx::query_scalar("SELECT count(*) FROM contacts WHERE id = $1")
        .bind(contact_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(contact_count, 0, "contact row must be gone");

    let pm_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM contact_payment_methods WHERE contact_id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        pm_count, 0,
        "the payment method row must be gone too, via the FK cascade"
    );
}

/// A provider detach failure must leave the contact and its payment method
/// row in place and surface the error, rather than the contact being
/// deleted regardless.
#[sqlx::test]
async fn a_provider_detach_failure_leaves_the_contact_in_place(pool: PgPool) {
    stripe_stub_base();
    seed_stripe_gateway(&pool).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let contact_id = seed_contact(&pool).await;
    let provider_pm_id = format!("pm_fail_{}", Uuid::new_v4().simple());
    seed_payment_method(&pool, contact_id, &provider_pm_id).await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete contact");
    assert!(
        resp.status().is_server_error() || resp.status() == StatusCode::BAD_GATEWAY,
        "PMS-1369: a provider detach failure must surface as an error, got {}",
        resp.status()
    );

    assert!(
        detach_calls().lock().unwrap().contains(&provider_pm_id),
        "PMS-1369: the detach must have been attempted"
    );

    let contact_count: i64 = sqlx::query_scalar("SELECT count(*) FROM contacts WHERE id = $1")
        .bind(contact_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        contact_count, 1,
        "PMS-1369: the contact must survive a failed detach"
    );

    let pm_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM contact_payment_methods WHERE contact_id = $1")
            .bind(contact_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        pm_count, 1,
        "PMS-1369: the payment method row must survive a failed detach too"
    );
}

/// PMS-1381 (F3): `detach_all_for_contact` must run its gateway calls
/// concurrently, not one row at a time. Four saved cards, each simulating a
/// `SLOW_DETACH_DELAY` gateway round trip, must together take close to one
/// call's latency rather than the sum of all four: a sequential loop would
/// take at least `4 * SLOW_DETACH_DELAY`, comfortably past the threshold
/// below, while a concurrent `try_join_all` finishes in roughly one delay
/// plus scheduling noise.
#[sqlx::test]
async fn detaching_a_contacts_saved_cards_runs_the_gateway_calls_concurrently(pool: PgPool) {
    stripe_stub_base();
    seed_stripe_gateway(&pool).await;
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let contact_id = seed_contact(&pool).await;
    const CARD_COUNT: usize = 4;
    let mut provider_pm_ids = Vec::with_capacity(CARD_COUNT);
    for i in 0..CARD_COUNT {
        let provider_pm_id = format!("pm_slow_{}", Uuid::new_v4().simple());
        if i == 0 {
            // Only one row may carry `is_default = TRUE` per contact
            // (`idx_contact_payment_methods_one_default`).
            seed_payment_method(&pool, contact_id, &provider_pm_id).await;
        } else {
            sqlx::query(
                "INSERT INTO contact_payment_methods \
                 (id, tenant_id, contact_id, provider, provider_pm_id, brand, last4, exp_month, exp_year, is_default) \
                 VALUES ($1, $2, $3, 'stripe', $4, 'visa', '4242', 12, 2030, FALSE)",
            )
            .bind(Uuid::new_v4())
            .bind(common::DEFAULT_TENANT_ID)
            .bind(contact_id)
            .bind(&provider_pm_id)
            .execute(&pool)
            .await
            .expect("seed non-default contact_payment_methods");
        }
        provider_pm_ids.push(provider_pm_id);
    }

    let started = std::time::Instant::now();
    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/contacts/contacts/{contact_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete contact");
    let elapsed = started.elapsed();
    assert!(
        resp.status().is_success(),
        "PMS-1381: delete should 2xx once every concurrent detach succeeds, got {}",
        resp.status()
    );

    for provider_pm_id in &provider_pm_ids {
        assert!(
            detach_calls().lock().unwrap().contains(provider_pm_id),
            "PMS-1381: every card's detach must have been called"
        );
    }

    // A sequential loop over 4 cards would take at least 4 * 200ms = 800ms;
    // a concurrent run finishes in roughly one 200ms round trip plus
    // per-call overhead (provider lookup, HTTP client setup) that stacks up
    // under load even when the sleeps themselves overlap. The threshold sits
    // well below the sequential floor while staying comfortably above one
    // call's latency, so it still fails on a sequential loop without being
    // sensitive to sandboxed-CI scheduling noise.
    assert!(
        elapsed < SLOW_DETACH_DELAY * 3,
        "PMS-1381: {CARD_COUNT} concurrent detach calls took {elapsed:?}, \
         expected close to one call's latency ({SLOW_DETACH_DELAY:?}), not the sum of all {CARD_COUNT}"
    );
}
