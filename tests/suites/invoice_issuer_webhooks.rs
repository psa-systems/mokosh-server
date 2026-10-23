//! MAPPS-1136: the Xero and QuickBooks webhook receivers, end to end.
//!
//! MAPPS-1099 Phase 3 shipped the two signature verifiers with nothing
//! mounting them, and no caller could have existed: nothing stored a
//! signing key. The key lives on the credential blob now, beside the
//! `client_id` and `client_secret` that are already per tenant, and these
//! are the routes that read it.
//!
//! The provider is a stub here for the same reason it is in
//! `invoice_issuer_delegation`: neither provider's delivery carries the
//! invoice's state. Xero sends a resource id and a category, Intuit sends
//! an entity name and an id, and both mean "this changed, come and look",
//! so the receiver comes and looks. The stub is what it looks at.
//!
//! What matters most here is what does NOT happen: an unsigned or
//! wrongly-signed delivery changes nothing and is recorded as refused, a
//! delivery for an invoice this tenant does not hold is accepted and
//! ignored rather than retried forever, and a second delivery of the same
//! event does not take the money twice.

use crate::common;

use std::sync::{Arc, Mutex};

use axum::{extract::State, response::IntoResponse, Json};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{Duration, NaiveDate, Utc};
use hmac::{Hmac, Mac};
use mokosh_server::db::Database;
use mokosh_server::modules::billing::invoice_issuer::InvoiceProviderKind;
use mokosh_server::modules::billing::invoice_issuer_credentials::{
    serialize_blob, IntegrationCredentialBlob, QuickbooksBlob, XeroBlob,
};
use mokosh_server::modules::billing::invoice_issuer_dispatch::IssuerDispatcher;
use mokosh_server::modules::billing::invoice_issuer_mappings::InvoiceIssuerMappingService;
use mokosh_server::modules::billing::provider_invoice::{QuickBooksClient, XeroClient};
use mokosh_server::modules::billing::service::BillingService;
use mokosh_server::modules::billing::webhook_invoice_issuer::{
    invoice_issuer_webhook_handler, InvoiceIssuerWebhookState,
};
use mokosh_server::modules::features::{Feature, FeatureSnapshot, FeatureToggles};
use mokosh_server::modules::integrations::IntegrationsService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
use mokosh_test::mokosh_test;
use reqwest::StatusCode;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// The webhook key this tenant's connection carries. A fixture value, and
/// the only thing a delivery has to prove it knows.
const SIGNING_KEY: &str = "fixture-webhook-key";
const XERO_INVOICE_ID: &str = "9f1d1c62-0f3a-4a1e-9c6f-7b2c9d4e5a60";
const QBO_INVOICE_ID: &str = "1042";

/// What the stub provider reports when asked for an invoice.
#[derive(Clone, Default)]
struct Script {
    xero_status: Arc<Mutex<String>>,
    qbo_balance: Arc<Mutex<f64>>,
    fetches: Arc<Mutex<usize>>,
}

async fn xero_invoice(State(script): State<Script>) -> impl IntoResponse {
    *script.fetches.lock().unwrap() += 1;
    let status = script.xero_status.lock().unwrap().clone();
    Json(json!({
        "Invoices": [{
            "InvoiceID": XERO_INVOICE_ID,
            "InvoiceNumber": "INV-0042",
            "Status": status,
        }]
    }))
}

async fn qbo_invoice(State(script): State<Script>) -> impl IntoResponse {
    *script.fetches.lock().unwrap() += 1;
    let balance = *script.qbo_balance.lock().unwrap();
    Json(json!({
        "Invoice": {
            "Id": QBO_INVOICE_ID,
            "DocNumber": QBO_INVOICE_ID,
            "SyncToken": "1",
            "Balance": balance,
            "TotalAmt": 300.0,
        }
    }))
}

async fn start_stub() -> (Script, String) {
    let script = Script::default();
    *script.xero_status.lock().unwrap() = "AUTHORISED".to_string();
    *script.qbo_balance.lock().unwrap() = 300.0;
    let app = axum::Router::new()
        .route(
            "/api.xro/2.0/Invoices/{id}",
            axum::routing::get(xero_invoice),
        )
        .route(
            "/v3/company/{realm}/invoice/{id}",
            axum::routing::get(qbo_invoice),
        )
        .with_state(script.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (script, base)
}

/// The receiver, mounted the way `create_api_router` mounts it.
async fn receiver(
    pool: &PgPool,
    base: &str,
    provider: InvoiceProviderKind,
) -> (axum::Router, Arc<dyn SecretProvider>, Database) {
    let app_pool = common::build_app_role_pool(pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let dispatcher = Arc::new(IssuerDispatcher::new(
        FeatureSnapshot::new(FeatureToggles::from_rows([(
            Feature::DelegatedInvoiceIssuer.key(),
            true,
        )])),
        Arc::new(IntegrationsService::new(db.clone(), secrets.clone())),
        Arc::new(InvoiceIssuerMappingService::new(db.clone())),
        secrets.clone(),
        Arc::new(
            XeroClient::new()
                .with_api_base(base)
                .with_identity_base(base),
        ),
        Arc::new(
            QuickBooksClient::new()
                .with_api_base(base)
                .with_identity_base(base),
        ),
    ));
    let state = Arc::new(InvoiceIssuerWebhookState {
        billing: Arc::new(BillingService::new(db.clone())),
        dispatcher,
        provider,
    });
    let router = axum::Router::new()
        .route(
            "/webhooks/{tenant_id}",
            axum::routing::post(invoice_issuer_webhook_handler),
        )
        .with_state(state);
    (router, secrets, db)
}

/// POST a delivery to the receiver, signed with `key`.
async fn deliver(
    router: &axum::Router,
    provider: InvoiceProviderKind,
    body: &Value,
    key: &str,
) -> StatusCode {
    use tower::ServiceExt;
    let raw = serde_json::to_vec(body).expect("serialise");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("key");
    mac.update(&raw);
    let signature = BASE64_STANDARD.encode(mac.finalize().into_bytes());
    let header = match provider {
        InvoiceProviderKind::Xero => "x-xero-signature",
        InvoiceProviderKind::Quickbooks => "intuit-signature",
    };
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/webhooks/{}", common::DEFAULT_TENANT_ID))
        .header("content-type", "application/json")
        .header(header, signature)
        .body(axum::body::Body::from(raw))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the receiver answers");
    StatusCode::from_u16(response.status().as_u16()).expect("status")
}

async fn seed_blob(
    secrets: &Arc<dyn SecretProvider>,
    provider: InvoiceProviderKind,
    key: Option<&str>,
) {
    let blob = match provider {
        InvoiceProviderKind::Xero => IntegrationCredentialBlob::Xero(XeroBlob {
            client_id: "fixture-id".to_string(),
            client_secret: "fixture-only-not-a-credential".to_string(),
            refresh_token: "fixture-rotating-value".to_string(),
            access_token: "fixture-bearer".to_string(),
            access_token_expires_at: Utc::now() + Duration::minutes(55),
            tenant_id: "xero-org-1".to_string(),
            webhook_signing_key: key.map(str::to_string),
        }),
        InvoiceProviderKind::Quickbooks => IntegrationCredentialBlob::Quickbooks(QuickbooksBlob {
            client_id: "fixture-id".to_string(),
            client_secret: "fixture-only-not-a-credential".to_string(),
            refresh_token: "fixture-rotating-value".to_string(),
            access_token: "fixture-bearer".to_string(),
            access_token_expires_at: Utc::now() + Duration::minutes(55),
            realm_id: "4620816365".to_string(),
            refresh_token_expires_at: Some(Utc::now() + Duration::days(90)),
            verifier_token: key.map(str::to_string),
        }),
    };
    secrets
        .put(
            &SecretKey::integration(common::DEFAULT_TENANT_ID, provider.as_str()),
            &serialize_blob(&blob).expect("serialise"),
        )
        .await
        .expect("seed the blob");
}

/// A delegated invoice, in the state MAPPS-1135 creates it: `sent`, with
/// the provider's identifiers on it.
async fn seed_delegated_invoice(pool: &PgPool, provider: &str, external_id: &str) -> Uuid {
    let company_id = common::seed_company(pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, invoice_number, company_id, status, \
             invoice_date, due_date, subtotal, tax_amount, discount_amount, total, \
             amount_paid, balance_due, currency, sent_at, \
             external_provider, external_invoice_id, external_number) \
         VALUES ($1, $2, $3, $4, 'sent', $5, $6, 300, 0, 0, 300, 0, 300, 'USD', NOW(), \
                 $7, $8, 'INV-0042')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("INV-{}", &id.to_string()[..8]))
    .bind(company_id)
    .bind(NaiveDate::from_ymd_opt(2026, 10, 1).unwrap())
    .bind(NaiveDate::from_ymd_opt(2026, 10, 31).unwrap())
    .bind(provider)
    .bind(external_id)
    .execute(pool)
    .await
    .expect("seed a delegated invoice");
    id
}

fn xero_delivery(resource_id: &str) -> Value {
    json!({
        "events": [{
            "resourceId": resource_id,
            "eventCategory": "INVOICE",
            "eventType": "UPDATE",
            "tenantId": "xero-org-1",
        }],
        "firstEventSequence": 1,
        "lastEventSequence": 1,
    })
}

fn qbo_delivery(id: &str) -> Value {
    json!({
        "eventNotifications": [{
            "realmId": "4620816365",
            "dataChangeEvent": {
                "entities": [{
                    "name": "Invoice",
                    "id": id,
                    "operation": "Update",
                    "lastUpdated": "2026-10-23T12:00:00-0700",
                }]
            }
        }]
    })
}

async fn invoice_state(pool: &PgPool, id: Uuid) -> (String, Decimal) {
    sqlx::query_as("SELECT status, balance_due FROM invoices WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read the invoice")
}

async fn payment_count(pool: &PgPool, invoice_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE invoice_id = $1")
        .bind(invoice_id)
        .fetch_one(pool)
        .await
        .expect("count payments")
}

async fn deliveries(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT provider, outcome FROM payment_webhook_deliveries ORDER BY received_at")
        .fetch_all(pool)
        .await
        .expect("read deliveries")
}

/// Xero says paid: Mokosh records what Xero collected and the one writer
/// derives the rest.
#[mokosh_test]
async fn a_paid_event_records_what_the_provider_collected(pool: PgPool) {
    let (script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    let invoice_id = seed_delegated_invoice(&pool, "xero", XERO_INVOICE_ID).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Xero).await;
    seed_blob(&secrets, InvoiceProviderKind::Xero, Some(SIGNING_KEY)).await;
    *script.xero_status.lock().unwrap() = "PAID".to_string();

    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &xero_delivery(XERO_INVOICE_ID),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        invoice_state(&pool, invoice_id).await,
        ("paid".to_string(), Decimal::ZERO),
        "the payment went through `recompute_invoice_balance`, which owns both"
    );
    assert_eq!(payment_count(&pool, invoice_id).await, 1);
    assert_eq!(
        deliveries(&pool).await,
        vec![("xero".to_string(), "accepted".to_string())]
    );

    // A provider re-delivers. The money is not taken twice.
    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &xero_delivery(XERO_INVOICE_ID),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payment_count(&pool, invoice_id).await,
        1,
        "idempotent on the provider's own invoice id"
    );
    assert_eq!(
        deliveries(&pool).await.last().map(|d| d.1.clone()),
        Some("ignored".to_string()),
        "and the second delivery says it changed nothing, rather than claiming a payment"
    );
    assert_eq!(
        *script.fetches.lock().unwrap(),
        2,
        "each delivery asked Xero"
    );
}

/// QuickBooks, same contract through its own wire shape.
#[mokosh_test]
async fn quickbooks_reports_a_payment_the_same_way(pool: PgPool) {
    let (script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    let invoice_id = seed_delegated_invoice(&pool, "quickbooks", QBO_INVOICE_ID).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Quickbooks).await;
    seed_blob(&secrets, InvoiceProviderKind::Quickbooks, Some(SIGNING_KEY)).await;
    // QBO reports payment as a zero balance, not as a status string.
    *script.qbo_balance.lock().unwrap() = 0.0;

    let status = deliver(
        &router,
        InvoiceProviderKind::Quickbooks,
        &qbo_delivery(QBO_INVOICE_ID),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        invoice_state(&pool, invoice_id).await,
        ("paid".to_string(), Decimal::ZERO)
    );
}

/// Xero voided its own invoice, so Mokosh voids the mirror.
///
/// Not through `void_invoice`, which refuses anything past draft on the
/// grounds that the customer holds the document and a credit note is the
/// instrument. The document the customer holds here is Xero's, and Xero
/// voided it.
#[mokosh_test]
async fn a_voided_event_voids_the_local_mirror(pool: PgPool) {
    let (script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    let invoice_id = seed_delegated_invoice(&pool, "xero", XERO_INVOICE_ID).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Xero).await;
    seed_blob(&secrets, InvoiceProviderKind::Xero, Some(SIGNING_KEY)).await;
    *script.xero_status.lock().unwrap() = "VOIDED".to_string();

    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &xero_delivery(XERO_INVOICE_ID),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _balance) = invoice_state(&pool, invoice_id).await;
    assert_eq!(status, "void");
    let reason: Option<String> =
        sqlx::query_scalar("SELECT void_reason FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&pool)
            .await
            .expect("read the reason");
    assert!(
        reason.unwrap_or_default().contains("xero"),
        "the reason names who voided it, because no person here did"
    );
    assert_eq!(payment_count(&pool, invoice_id).await, 0);
}

/// A delivery nobody signed, and one signed with the wrong key, change
/// nothing.
#[mokosh_test]
async fn an_unverified_delivery_changes_nothing(pool: PgPool) {
    let (script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    let invoice_id = seed_delegated_invoice(&pool, "xero", XERO_INVOICE_ID).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Xero).await;
    seed_blob(&secrets, InvoiceProviderKind::Xero, Some(SIGNING_KEY)).await;
    *script.xero_status.lock().unwrap() = "PAID".to_string();

    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &xero_delivery(XERO_INVOICE_ID),
        "not-the-key",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        invoice_state(&pool, invoice_id).await,
        ("sent".to_string(), Decimal::from(300)),
        "an invoice is not paid because somebody said so without the key"
    );
    assert_eq!(
        *script.fetches.lock().unwrap(),
        0,
        "and the provider is never asked: nothing in that body was believed"
    );
    assert_eq!(
        deliveries(&pool).await,
        vec![("xero".to_string(), "refused".to_string())],
        "refused and failed are different things, and this is the first"
    );
}

/// A tenant with no stored key refuses every delivery and records
/// nothing, because this route is unauthenticated by construction.
#[mokosh_test]
async fn a_connection_without_a_key_refuses_and_records_nothing(pool: PgPool) {
    let (_script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    seed_delegated_invoice(&pool, "xero", XERO_INVOICE_ID).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Xero).await;
    seed_blob(&secrets, InvoiceProviderKind::Xero, None).await;

    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &xero_delivery(XERO_INVOICE_ID),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        deliveries(&pool).await.is_empty(),
        "recording before a connection is known to exist would let anyone who learns \
         the URL write history into any tenant id they can name"
    );
}

/// A delivery for an invoice this tenant does not hold is accepted and
/// ignored. Both providers multiplex every subscribed resource onto one
/// stream, and an error would make them retry it forever.
#[mokosh_test]
async fn a_delivery_for_an_unknown_invoice_is_ignored_not_retried(pool: PgPool) {
    let (script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    seed_delegated_invoice(&pool, "xero", XERO_INVOICE_ID).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Xero).await;
    seed_blob(&secrets, InvoiceProviderKind::Xero, Some(SIGNING_KEY)).await;

    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &xero_delivery("00000000-0000-0000-0000-00000000dead"),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a 500 here means retries forever");
    assert_eq!(
        *script.fetches.lock().unwrap(),
        0,
        "and no call to the provider for an invoice we do not hold"
    );
    assert_eq!(
        deliveries(&pool).await,
        vec![("xero".to_string(), "ignored".to_string())]
    );
}

/// Xero's "intent to receive" validation carries no events and must
/// answer 2xx, or the subscription is never activated.
#[mokosh_test]
async fn the_intent_to_receive_call_is_answered(pool: PgPool) {
    let (_script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Xero).await;
    seed_blob(&secrets, InvoiceProviderKind::Xero, Some(SIGNING_KEY)).await;

    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &json!({ "events": [], "firstEventSequence": 0, "lastEventSequence": 0 }),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        deliveries(&pool).await,
        vec![("xero".to_string(), "ignored".to_string())]
    );
}

/// An invoice the provider has not been paid for is left alone.
#[mokosh_test]
async fn an_open_invoice_is_left_as_it_is(pool: PgPool) {
    let (script, base) = start_stub().await;
    common::seed_admin(&pool).await;
    let invoice_id = seed_delegated_invoice(&pool, "xero", XERO_INVOICE_ID).await;
    let (router, secrets, _db) = receiver(&pool, &base, InvoiceProviderKind::Xero).await;
    seed_blob(&secrets, InvoiceProviderKind::Xero, Some(SIGNING_KEY)).await;
    *script.xero_status.lock().unwrap() = "AUTHORISED".to_string();

    let status = deliver(
        &router,
        InvoiceProviderKind::Xero,
        &xero_delivery(XERO_INVOICE_ID),
        SIGNING_KEY,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        invoice_state(&pool, invoice_id).await,
        ("sent".to_string(), Decimal::from(300))
    );
    assert_eq!(payment_count(&pool, invoice_id).await, 0);
}
