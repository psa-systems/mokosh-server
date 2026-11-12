//! PMS-1312: whether a payment provider is connected lives in `integrations`.
//!
//! The unit tests in `modules::integrations` cover the registry's shape and
//! `billing::service::retired_gateway_flag` covers the source rule that no
//! serving read consults the retired column. What needs a database and a booted
//! app is the thing those cannot show: that the two surfaces which set this one
//! fact agree, in both directions, and that what the payment path serves follows
//! from it.
//!
//! Each test drives real routes rather than the service, because the whole point
//! of the move is that an operator can connect a gateway from either page and
//! meet the same answer.

use crate::common;

use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// A Stripe credential blob that `StripeProvider::from_config` accepts, so a
/// gateway seeded with it is one the payment path can actually build. Nothing
/// here reaches the network.
fn stripe_config() -> Value {
    json!({ "secret_key": "sk_test_connection_home", "webhook_secret": "whsec_connection_home" })
}

async fn put_gateway(
    app: &common::TestApp,
    token: &str,
    provider: &str,
    is_active: bool,
    config: Option<Value>,
) -> reqwest::Response {
    let mut body = json!({
        "provider": provider,
        "is_active": is_active,
        "is_test_mode": true,
    });
    if let Some(config) = config {
        body["config"] = config;
    }
    app.client
        .put(app.url("/api/v1/payment-gateways"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("put gateway")
}

// MAPPS-1098: the `connect` / `disconnect` helpers that drove the removed
// tests above went with them. The two surviving tests here drive the
// payment lifecycle through `/payment-gateways` only.

/// The three-state connection status for a payment provider, derived from
/// the payments list the same way the integrations table's status would
/// read for one.
///
/// Rewritten under MAPPS-1098 (payment providers moved off the
/// `/integrations` HTTP surface) to read from `/payment-gateways` instead.
/// The semantics are identical: `payment_gateway_configs.configured`
/// mirrors whether a credential is stored, and `is_active` is the
/// one-writer flag `CONNECTED_GATEWAY_FLAG` reads to decide whether the
/// provider serves. A row absent from the list means the tenant has not
/// touched the provider, which is `not_connected`.
async fn integration_status(app: &common::TestApp, token: &str, provider: &str) -> String {
    let response = app
        .client
        .get(app.url("/api/v1/payment-gateways"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list gateways");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("gateway list json");
    let items = body["data"].as_array().expect("a list of gateways");
    let row = items.iter().find(|r| r["provider"] == provider);
    match row {
        None => "not_connected".to_string(),
        Some(r) => {
            let is_active = r["is_active"].as_bool().unwrap_or(false);
            let configured = r["configured"].as_bool().unwrap_or(false);
            match (configured, is_active) {
                (_, true) => "connected".to_string(),
                (true, false) => "disconnected".to_string(),
                (false, false) => "not_connected".to_string(),
            }
        }
    }
}

/// What the payments settings page shows for this provider's switch.
async fn listed_is_active(app: &common::TestApp, token: &str, provider: &str) -> bool {
    let response = app
        .client
        .get(app.url("/api/v1/payment-gateways"))
        .bearer_auth(token)
        .send()
        .await
        .expect("list gateways");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("gateway list json");
    let items = body["data"].as_array().expect("a list of gateways");
    items
        .iter()
        .find(|row| row["provider"] == provider)
        .map(|row| row["is_active"].as_bool().unwrap_or(false))
        .unwrap_or(false)
}

/// The retired mirror, read straight out of the table. Nothing in the build reads
/// it; this asserts the rollback promise migration 256 makes.
async fn mirror(pool: &PgPool, provider: &str) -> Option<bool> {
    sqlx::query_scalar(
        "SELECT is_active FROM payment_gateway_configs WHERE tenant_id = $1 AND provider = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .fetch_optional(pool)
    .await
    .expect("read the retired mirror")
    .flatten()
}

// MAPPS-1098: `readiness_has_gateway` and `seed_sent_invoice` serviced
// the removed `connecting_on_the_integrations_page_is_what_the_payment_path_serves`
// test. The surviving tests do not exercise invoice readiness directly.
#[allow(dead_code)]
async fn seed_sent_invoice(pool: &PgPool, company_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
         invoice_date, due_date, subtotal, total, amount_paid, balance_due, currency) \
         VALUES ($1, $2, $3, $4, 'sent', CURRENT_DATE, CURRENT_DATE + 30, 100, 100, 0, 100, 'USD')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("PCH-INV-{}", &id.simple().to_string()[..8]))
    .bind(company_id)
    .execute(pool)
    .await
    .expect("seed sent invoice");
    id
}

/// The one fact, from both surfaces. Saving the gateway with `is_active: true`
/// is what an admin does today, and the integrations page has to report the same
/// thing without a second switch to flip.
#[mokosh_test]
async fn saving_an_active_gateway_connects_it_on_the_integrations_page(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    assert_eq!(
        integration_status(&app, &token, "stripe").await,
        "not_connected",
        "a tenant with no gateway has not connected Stripe"
    );

    let response = put_gateway(&app, &token, "stripe", true, Some(stripe_config())).await;
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        integration_status(&app, &token, "stripe").await,
        "connected"
    );
    assert!(listed_is_active(&app, &token, "stripe").await);
    assert_eq!(
        mirror(&pool, "stripe").await,
        Some(true),
        "the retired mirror follows the fact, for a rolled-back image"
    );

    // And off again, through the same surface.
    let response = put_gateway(&app, &token, "stripe", false, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        integration_status(&app, &token, "stripe").await,
        "disconnected",
        "switching a saved gateway off is the deliberate act, not `not_connected`"
    );
    assert!(!listed_is_active(&app, &token, "stripe").await);
    assert_eq!(mirror(&pool, "stripe").await, Some(false));
}

// MAPPS-1098: `connecting_on_the_integrations_page_is_what_the_payment_path_serves`
// and `connecting_a_payment_gateway_refuses_the_states_that_would_lie` were
// removed with this ticket. Both exercised the integrations
// `/connect` and `/disconnect` endpoints for Stripe + PayPal, which 1098
// turned into 404s: the payment-provider lifecycle lives entirely on
// `/payment-gateways` now, and the credential-refusal path from
// PMS-1312 is no longer reachable because there is no HTTP surface here
// to send a credential to. The write-through to `integrations.status`
// stays covered by `saving_an_active_gateway_connects_it_on_the_integrations_page`
// above, which runs through `/payment-gateways` and asserts the row
// still carries the connected state.

/// `authorize_net` is in the gateway table's CHECK and in no registry entry, so
/// saving one must not try to write an `integrations` row for it. Before the skip
/// was written this was a constraint violation on an ordinary save.
#[mokosh_test]
async fn saving_a_gateway_with_no_registry_entry_still_works(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let response = put_gateway(
        &app,
        &token,
        "authorize_net",
        false,
        Some(json!({ "api_login_id": "x", "transaction_key": "y" })),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "storing credentials for an unimplemented provider is allowed (PMS-966)"
    );

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM integrations WHERE tenant_id = $1 AND provider = 'authorize_net'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count integrations rows");
    assert_eq!(
        rows, 0,
        "a provider the integrations CHECK refuses gets no row here"
    );
}

/// What migration 256 wrote, for the assertions below.
///
/// A named row rather than a tuple: four columns with a `Vec` and an `Option` in
/// them is `clippy::type_complexity`, which the workspace denies, and the field
/// names are what make the assertions readable anyway (`paypal.status` rather
/// than `paypal.1`). The same reason `MembershipViewRow` exists in `db::identity`.
#[derive(Debug, sqlx::FromRow)]
struct BackfilledRow {
    provider: String,
    status: String,
    enabled_capabilities: Vec<String>,
    connected_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The backfill migration 256 runs, re-run against rows it never saw.
///
/// The template database this suite clones already has 256 applied, so there is
/// no way to seed a gateway "before" it. Re-executing the file is the next best
/// thing and tests the part that matters: whether the mapping it claims is the
/// mapping it performs. The file is executed rather than transcribed, because a
/// copy of the statement in a test can agree with the test and disagree with the
/// migration.
///
/// It also pins the idempotency the `ON CONFLICT DO NOTHING` promises, since a
/// deployment that takes this release twice (a rollback and a roll forward) runs
/// it against rows that already have their row.
#[mokosh_test]
async fn the_backfill_maps_each_gateway_the_way_it_says(pool: PgPool) {
    let tenant = common::DEFAULT_TENANT_ID;
    // Three shapes: switched on, saved and never switched on, and a provider the
    // integrations CHECK refuses.
    for (provider, is_active) in [("stripe", true), ("paypal", false), ("authorize_net", true)] {
        sqlx::query(
            "INSERT INTO payment_gateway_configs \
                 (tenant_id, provider, is_active, is_test_mode, config_encrypted) \
             VALUES ($1, $2, $3, TRUE, 'ciphertext')",
        )
        .bind(tenant)
        .bind(provider)
        .bind(is_active)
        .execute(&pool)
        .await
        .expect("seed a pre-migration gateway row");
    }

    let migration = include_str!("../../migrations/256_payment_gateway_connection_home.sql");
    for _ in 0..2 {
        sqlx::raw_sql(migration)
            .execute(&pool)
            .await
            .expect("run the backfill");
    }

    let rows: Vec<BackfilledRow> = sqlx::query_as(
        "SELECT provider, status, enabled_capabilities, connected_at FROM integrations \
             WHERE tenant_id = $1 ORDER BY provider",
    )
    .bind(tenant)
    .fetch_all(&pool)
    .await
    .expect("read the backfilled rows");

    assert_eq!(
        rows.len(),
        2,
        "one row per gateway the integrations CHECK accepts, and none for \
         authorize_net: {rows:?}"
    );

    let paypal = &rows[0];
    assert_eq!(paypal.provider, "paypal");
    assert_eq!(
        paypal.status, "not_connected",
        "an inactive row could be either 'saved and never switched on' or \
         'switched off', and nothing stored says which, so it maps to the status \
         that asserts neither"
    );
    assert!(
        paypal.connected_at.is_none(),
        "and it claims no connect that may never have happened"
    );

    let stripe = &rows[1];
    assert_eq!(stripe.provider, "stripe");
    assert_eq!(stripe.status, "connected");
    assert!(stripe.connected_at.is_some(), "an active row records when");
    assert_eq!(
        stripe.enabled_capabilities,
        vec!["payments".to_string()],
        "never the provider's whole supported set: enabling `invoicing` would \
         claim this tenant handed their invoice issuing to Stripe"
    );
    assert_eq!(paypal.enabled_capabilities, vec!["payments".to_string()]);
}
