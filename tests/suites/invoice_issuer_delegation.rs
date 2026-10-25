//! MAPPS-1134: `create_invoice` through the delegated issuer, end to end.
//!
//! MAPPS-1099 shipped both provider clients, the dispatcher, the mapping
//! tables and the credential blobs over ten PRs, and left the last wire
//! unconnected: `BillingService` refused a delegated tenant rather than
//! calling `IssuerDispatcher::plan`. The wrap-up says why - the harness it
//! was written in could not stand up Xero and QuickBooks stubs - so the
//! refusal was the honest state to ship.
//!
//! This is that harness. Both clients take `with_api_base` /
//! `with_identity_base`, every dependency of `IssuerDispatcher::new` is
//! injected, and this file points the pair at an axum stub on
//! `127.0.0.1:0`, which is what a dozen other suites here already do for
//! Google, Apple, PayPal and bunyip.
//!
//! What only an integration test can show, and what the unit tests on the
//! dispatcher cannot: that the external call happens BEFORE the local
//! write, so a provider that refuses leaves no invoice row and burns no
//! number from the tenant's sequence; and that a deployment with the flag
//! off reaches no provider at all.

use crate::common;

use std::sync::{Arc, Mutex};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{Duration, NaiveDate, Utc};
use mokosh_server::db::Database;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::invoice_issuer::InvoiceProviderKind;
use mokosh_server::modules::billing::invoice_issuer_credentials::{
    serialize_blob, IntegrationCredentialBlob, QuickbooksBlob, XeroBlob,
};
use mokosh_server::modules::billing::invoice_issuer_dispatch::IssuerDispatcher;
use mokosh_server::modules::billing::invoice_issuer_mappings::InvoiceIssuerMappingService;
use mokosh_server::modules::billing::models::{
    CreateInvoiceLineRequest, CreateInvoiceRequest, InvoiceLineType,
};
use mokosh_server::modules::billing::provider_invoice::{QuickBooksClient, XeroClient};
use mokosh_server::modules::billing::service::BillingService;
use mokosh_server::modules::features::{Feature, FeatureSnapshot, FeatureToggles};
use mokosh_server::modules::integrations::IntegrationsService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
use mokosh_test::mokosh_test;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// What a stub provider was asked for, and what it answers.
///
/// Counting the calls is half the point of this file: the flag-off and
/// not-delegated cases are only convincing if the provider was never
/// reached, and "the columns are NULL" alone would also be true of a call
/// that happened and was ignored.
#[derive(Default)]
struct Calls {
    issue: Vec<Value>,
    token: usize,
    /// When set, the issue endpoint answers this status with a plain body
    /// instead of an invoice.
    refuse_with: Option<StatusCode>,
}

type Stub = Arc<Mutex<Calls>>;

async fn xero_issue(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.issue.push(body);
    if let Some(status) = calls.refuse_with {
        return (status, Json(json!({ "Message": "the provider refused" })));
    }
    (
        StatusCode::OK,
        Json(json!({
            "Invoices": [{
                "InvoiceID": "9f1d1c62-0f3a-4a1e-9c6f-7b2c9d4e5a60",
                "InvoiceNumber": "INV-0042",
                "Status": "AUTHORISED",
            }]
        })),
    )
}

async fn quickbooks_issue(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.issue.push(body);
    if let Some(status) = calls.refuse_with {
        return (
            status,
            Json(json!({ "Fault": { "type": "ValidationFault" } })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "Invoice": { "Id": "1042", "DocNumber": "1042", "SyncToken": "0" }
        })),
    )
}

async fn token(State(stub): State<Stub>) -> impl IntoResponse {
    stub.lock().unwrap().token += 1;
    Json(json!({
        "access_token": "refreshed-access",
        "refresh_token": "rotated-refresh",
        "expires_in": 1800,
        "x_refresh_token_expires_in": 8_640_000,
        "token_type": "Bearer",
    }))
}

/// One stub serving both providers' endpoints, since a case only ever
/// delegates to one of them and the paths do not collide.
async fn start_stub() -> (Stub, String) {
    let stub: Stub = Arc::new(Mutex::new(Calls::default()));
    let app = axum::Router::new()
        .route("/api.xro/2.0/Invoices", axum::routing::post(xero_issue))
        .route(
            "/v3/company/{realm}/invoice",
            axum::routing::post(quickbooks_issue),
        )
        .route("/connect/token", axum::routing::post(token))
        .route("/oauth2/v1/tokens/bearer", axum::routing::post(token))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (stub, base)
}

/// A `BillingService` wired exactly as `create_api_router` wires the
/// serving one, except that the two clients point at the stub.
async fn service_with_dispatch(
    pool: &PgPool,
    base: &str,
    flag_on: bool,
) -> (BillingService, Database, Arc<dyn SecretProvider>) {
    let app_pool = common::build_app_role_pool(pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let toggles = if flag_on {
        FeatureToggles::from_rows([(Feature::DelegatedInvoiceIssuer.key(), true)])
    } else {
        FeatureToggles::default()
    };
    let dispatcher = IssuerDispatcher::new(
        FeatureSnapshot::new(toggles),
        Arc::new(IntegrationsService::new(db.clone(), secrets.clone())),
        Arc::new(InvoiceIssuerMappingService::new(db.clone())),
        secrets.clone(),
        Arc::new(fixture_apps()),
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
    );
    let billing = BillingService::new(db.clone()).with_invoice_dispatch(Arc::new(dispatcher));
    (billing, db, secrets)
}

/// The deployment's applications, as a fixture supplies them.
///
/// MAPPS-1139: the client id and secret are the HOST's, read from governed
/// application-tier secrets at boot, so a test supplies them here rather
/// than writing them into a tenant's blob.
fn fixture_apps() -> mokosh_server::modules::billing::invoice_issuer_app::IssuerApps {
    use mokosh_server::modules::billing::invoice_issuer_app::{IssuerApp, IssuerApps};
    let app = || {
        Some(IssuerApp {
            client_id: "fixture-app".to_string(),
            client_secret: "fixture-only-not-a-credential".to_string(),
            // No webhook subscription in these cases; the receivers' own
            // suite is where that key earns its keep.
            webhook_key: None,
        })
    };
    IssuerApps {
        xero: app(),
        quickbooks: app(),
    }
}

/// Delegate `Invoicing` for one provider on this tenant, the way the
/// integrations surface does.
async fn delegate(pool: &PgPool, tenant_id: Uuid, provider: &str) {
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, enabled_capabilities) \
         VALUES ($1, $2, 'connected', ARRAY['invoicing']::text[]) \
         ON CONFLICT (tenant_id, provider) DO UPDATE \
           SET status = 'connected', enabled_capabilities = EXCLUDED.enabled_capabilities",
    )
    .bind(tenant_id)
    .bind(provider)
    .execute(pool)
    .await
    .expect("delegate invoicing");
}

/// The stored OAuth state the dispatcher reads, built from the production
/// types and written with the production serialiser.
///
/// Not a `json!` literal. Two reasons, and the second is why it changed:
/// the fixture cannot drift from the shape the code parses, and a literal
/// object carrying `client_id`, `client_secret` and `refresh_token` is the
/// GCP authorized-user credential shape, which the secrets scan flags on
/// sight. Building the real struct keeps the keys where they already live,
/// in `src/`, and leaves this file with no credential-shaped literal for a
/// scanner to find or a future reader to copy.
///
/// The expiry is far enough out that the happy path does NOT refresh, so a
/// case that wants the refresh asks for it by passing a small value.
async fn seed_xero_blob(secrets: &Arc<dyn SecretProvider>, tenant_id: Uuid, expires_in_mins: i64) {
    let blob = IntegrationCredentialBlob::Xero(XeroBlob {
        refresh_token: "fixture-rotating-value".to_string(),
        access_token: "fixture-bearer".to_string(),
        access_token_expires_at: Utc::now() + Duration::minutes(expires_in_mins),
        tenant_id: "xero-org-1".to_string(),
        // No webhook subscription in these cases; MAPPS-1136's suite is
        // where that key earns its keep.
    });
    secrets
        .put(
            &SecretKey::integration(tenant_id, "xero"),
            &serialize_blob(&blob).expect("serialise the blob"),
        )
        .await
        .expect("seed the xero credential blob");
}

async fn seed_quickbooks_blob(secrets: &Arc<dyn SecretProvider>, tenant_id: Uuid) {
    let blob = IntegrationCredentialBlob::Quickbooks(QuickbooksBlob {
        refresh_token: "fixture-rotating-value".to_string(),
        access_token: "fixture-bearer".to_string(),
        access_token_expires_at: Utc::now() + Duration::minutes(55),
        realm_id: "4620816365".to_string(),
        refresh_token_expires_at: Some(Utc::now() + Duration::days(90)),
    });
    secrets
        .put(
            &SecretKey::integration(tenant_id, "quickbooks"),
            &serialize_blob(&blob).expect("serialise the blob"),
        )
        .await
        .expect("seed the quickbooks credential blob");
}

fn request(company_id: Uuid) -> CreateInvoiceRequest {
    CreateInvoiceRequest {
        company_id,
        billing_contact_id: None,
        contract_id: None,
        invoice_date: NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
        due_date: Some(NaiveDate::from_ymd_opt(2026, 10, 31).unwrap()),
        payment_terms: None,
        payment_term_id: None,
        tax_amount: None,
        tax_rate_id: None,
        discount_amount: None,
        currency: Some("USD".to_string()),
        notes: None,
        po_number: None,
        lines: vec![CreateInvoiceLineRequest {
            line_type: InvoiceLineType::Service,
            product_id: None,
            is_taxable: false,
            description: "Managed services, October".to_string(),
            quantity: Decimal::from(2),
            unit_price: Decimal::from(150),
            ticket_id: None,
            project_id: None,
            sort_order: 0,
        }],
    }
}

/// The five columns that record how an invoice was sent, read as one row.
///
/// A named type rather than a tuple because five is past where a reader can
/// keep the order straight, and `clippy::type_complexity` says so.
#[derive(sqlx::FromRow)]
struct SendColumns {
    status: String,
    sent_at: Option<chrono::DateTime<Utc>>,
    emailed_to: Option<String>,
    emailed_at: Option<chrono::DateTime<Utc>>,
    delivery_method: Option<String>,
}

/// A product this tenant sells, for the QuickBooks path.
///
/// QuickBooks refuses a line that does not name an item, so a delegated
/// QBO invoice needs a product on every line and a product mapping for
/// each one. Xero takes a free-text line and needs neither, which is the
/// kind of per-provider difference `issuer_delegation` gives as its
/// reason for two sibling clients rather than one generic.
async fn seed_product(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO products (id, tenant_id, name, unit_price) \
         VALUES ($1, $2, 'Managed services', 150) RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("seed a product")
}

/// The three external columns on a row, or `None` when no row exists.
async fn external_columns(
    pool: &PgPool,
    id: Uuid,
) -> Option<(Option<String>, Option<String>, Option<String>)> {
    sqlx::query_as("SELECT external_provider, external_invoice_id, external_number FROM invoices WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("read the invoice row")
}

async fn invoice_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(pool)
        .await
        .expect("count invoices")
}

async fn last_number(pool: &PgPool) -> Option<i32> {
    sqlx::query_scalar("SELECT last_number FROM invoice_sequences LIMIT 1")
        .fetch_optional(pool)
        .await
        .expect("read the sequence")
}

/// A tenant that delegated Invoicing to Xero has the invoice issued there,
/// and the local row records which provider holds it.
#[mokosh_test]
async fn a_delegated_tenant_has_the_invoice_issued_by_xero(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "xero").await;
    seed_xero_blob(&secrets, common::DEFAULT_TENANT_ID, 55).await;
    InvoiceIssuerMappingService::new(db.clone())
        .upsert_customer_mapping(
            tenant,
            InvoiceProviderKind::Xero,
            company_id,
            "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e",
        )
        .await
        .expect("map the company to a Xero contact");

    let created = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the invoice");

    // Copied out rather than asserted under the guard: `drop(calls)` before
    // the next await is not enough for `clippy::await_holding_lock`, which
    // reads the binding's scope and not the drop.
    let (issued, refreshes, sent) = {
        let calls = stub.lock().unwrap();
        (
            calls.issue.len(),
            calls.token,
            calls.issue.first().cloned().unwrap_or(Value::Null),
        )
    };
    assert_eq!(issued, 1, "Xero is asked exactly once");
    assert_eq!(
        refreshes, 0,
        "a token with 55 minutes left is not refreshed"
    );
    assert_eq!(sent["Type"], "ACCREC", "an accounts-receivable invoice");
    assert_eq!(sent["CurrencyCode"], "USD");
    assert_eq!(
        sent["LineItems"][0]["Description"], "Managed services, October",
        "the line reaches the provider: {sent}"
    );

    let columns = external_columns(&pool, created.id)
        .await
        .expect("the row exists");
    assert_eq!(columns.0.as_deref(), Some("xero"));
    assert_eq!(
        columns.1.as_deref(),
        Some("9f1d1c62-0f3a-4a1e-9c6f-7b2c9d4e5a60"),
        "the provider's own id is what a reconciliation reads back"
    );
    assert_eq!(
        columns.2.as_deref(),
        Some("INV-0042"),
        "and the number the customer sees is the provider's"
    );
    assert!(
        !created.invoice_number.is_empty(),
        "the local number is still minted: every existing Mokosh reference to this invoice uses it"
    );
}

/// MAPPS-1135: a delegated invoice is created `sent`, and the columns that
/// record how Mokosh sent it stay empty because Mokosh did not.
///
/// Left in draft it would be invisible to every receivables read, could not
/// be amended or written off, and could not take the payment a provider
/// webhook reports: `create_payment` refuses a draft (PMS-999), which is
/// asserted here too because Phase 3b depends on it.
#[mokosh_test]
async fn a_delegated_invoice_is_sent_by_the_provider_not_by_us(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "xero").await;
    seed_xero_blob(&secrets, common::DEFAULT_TENANT_ID, 55).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_customer_mapping(
            tenant,
            InvoiceProviderKind::Xero,
            company_id,
            "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e",
        )
        .await
        .expect("map the company");

    let created = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the invoice");
    assert_eq!(stub.lock().unwrap().issue.len(), 1);

    let row: SendColumns = sqlx::query_as(
        "SELECT status, sent_at, emailed_to, emailed_at, delivery_method \
         FROM invoices WHERE id = $1",
    )
    .bind(created.id)
    .fetch_one(&pool)
    .await
    .expect("read the row");

    assert_eq!(
        row.status, "sent",
        "the provider sent it, and sent means it went"
    );
    assert!(
        row.sent_at.is_some(),
        "and it went at a time worth recording"
    );
    assert_eq!(
        (row.emailed_to, row.emailed_at, row.delivery_method),
        (None, None, None),
        "Mokosh mailed nothing: a recipient or a method here would be a claim about \
         a delivery it did not make"
    );

    // What MAPPS-1136 needs from this ticket: the provider reports a
    // payment, and it has somewhere to land.
    let payment = billing
        .create_payment(
            tenant,
            &mokosh_server::modules::billing::models::CreatePaymentRequest {
                invoice_id: Some(created.id),
                company_id,
                payment_date: NaiveDate::from_ymd_opt(2026, 10, 5).unwrap(),
                amount: Decimal::from(300),
                payment_method: mokosh_server::modules::billing::models::PaymentMethod::Other,
                reference_number: Some("9f1d1c62-0f3a-4a1e-9c6f-7b2c9d4e5a60".to_string()),
                gateway_transaction_id: None,
                notes: Some("Reported paid by Xero".to_string()),
            },
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("a delegated invoice can take the payment its provider reports");
    assert_eq!(payment.amount, Decimal::from(300));

    let (status, balance): (String, Decimal) =
        sqlx::query_as("SELECT status, balance_due FROM invoices WHERE id = $1")
            .bind(created.id)
            .fetch_one(&pool)
            .await
            .expect("read the row back");
    assert_eq!(
        (status.as_str(), balance),
        ("paid", Decimal::ZERO),
        "and the one writer derives the rest, as it does for every other invoice"
    );
}

/// MAPPS-1147: a delegated invoice has no Mokosh document, and the PDF
/// route says so instead of rendering one.
///
/// The invoice is `sent` and therefore frozen, and deliberately has no
/// stored bytes, so the live-render fallback would otherwise fire and
/// answer a Mokosh-branded PDF carrying Mokosh's number for an invoice
/// Xero issued and delivered. An admin who forwarded it would have sent
/// their customer a second invoice.
#[mokosh_test]
async fn the_pdf_route_refuses_an_invoice_the_provider_issued(pool: PgPool) {
    let (_stub, base) = start_stub().await;
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "xero").await;
    seed_xero_blob(&secrets, common::DEFAULT_TENANT_ID, 55).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_customer_mapping(
            tenant,
            InvoiceProviderKind::Xero,
            company_id,
            "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e",
        )
        .await
        .expect("map the company");
    let delegated = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the delegated invoice");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let response = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{}/pdf", delegated.id)))
        .bearer_auth(&token)
        .send()
        .await
        .expect("ask for the pdf");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::CONFLICT,
        "a delegated invoice has no Mokosh document to serve"
    );
    let body = response.text().await.unwrap_or_default();
    assert!(
        body.contains("xero") && body.contains("INV-0042"),
        "the refusal says where the document is and under which number: {body}"
    );
}

/// A local invoice is untouched: still created `draft`, with no sent_at.
#[mokosh_test]
async fn a_local_invoice_is_still_a_draft(pool: PgPool) {
    let (_stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, _db, _secrets) = service_with_dispatch(&pool, &base, true).await;

    let created = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the invoice");

    let (status, sent_at): (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT status, sent_at FROM invoices WHERE id = $1")
            .bind(created.id)
            .fetch_one(&pool)
            .await
            .expect("read the row");
    assert_eq!(status, "draft");
    assert!(sent_at.is_none());
}

/// An access token near expiry is refreshed before the issue call, and the
/// rotated pair is written back.
#[mokosh_test]
async fn a_near_expiry_token_is_refreshed_before_the_invoice_is_issued(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "xero").await;
    // One minute left: inside anybody's definition of near expiry.
    seed_xero_blob(&secrets, common::DEFAULT_TENANT_ID, 1).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_customer_mapping(
            tenant,
            InvoiceProviderKind::Xero,
            company_id,
            "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e",
        )
        .await
        .expect("map the company");

    billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the invoice");

    assert_eq!(stub.lock().unwrap().token, 1, "the token was refreshed");

    let stored = secrets
        .get(&SecretKey::integration(common::DEFAULT_TENANT_ID, "xero"))
        .await
        .expect("read the blob back")
        .expect("the blob is still there");
    assert!(
        stored.contains("rotated-refresh"),
        "Xero rotates the refresh token on every refresh and the new one MUST be stored, \
         or the next call sees invalid_grant: {stored}"
    );
}

/// A provider that refuses leaves nothing behind: no invoice row, and no
/// number consumed from the tenant's sequence.
///
/// The second half is the one that needs the ordering to be right. A
/// dispatch called from inside the write transaction would roll the row
/// back too, but it would have taken the sequence lock and held it across
/// the provider round trip to do it.
#[mokosh_test]
async fn a_refused_invoice_leaves_no_row_and_burns_no_number(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "xero").await;
    seed_xero_blob(&secrets, common::DEFAULT_TENANT_ID, 55).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_customer_mapping(
            tenant,
            InvoiceProviderKind::Xero,
            company_id,
            "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e",
        )
        .await
        .expect("map the company");
    stub.lock().unwrap().refuse_with = Some(StatusCode::BAD_REQUEST);

    let before = last_number(&pool).await;
    let outcome = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await;

    assert!(outcome.is_err(), "the provider refused: {outcome:?}");
    assert_eq!(
        invoice_count(&pool).await,
        0,
        "no local row for an invoice the provider does not have"
    );
    assert_eq!(
        last_number(&pool).await,
        before,
        "and no number is consumed, so the tenant's sequence stays dense"
    );
}

/// A company with no mapping is a Conflict naming the admin route, not a
/// 500 and not a silent fall back to the local path.
#[mokosh_test]
async fn an_unmapped_company_says_where_to_set_the_mapping(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, _db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "xero").await;
    seed_xero_blob(&secrets, common::DEFAULT_TENANT_ID, 55).await;

    let err = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect_err("no mapping for this company");
    let message = err.to_string();
    assert!(
        message.contains("invoice-issuer-mappings"),
        "the message has to say where to fix it: {message}"
    );
    assert_eq!(
        stub.lock().unwrap().issue.len(),
        0,
        "and nothing is sent to the provider"
    );
    assert_eq!(invoice_count(&pool).await, 0, "and no row is written");
}

/// QuickBooks is the same contract through a different wire shape.
#[mokosh_test]
async fn a_delegated_tenant_has_the_invoice_issued_by_quickbooks(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "quickbooks").await;
    seed_quickbooks_blob(&secrets, common::DEFAULT_TENANT_ID).await;
    let product_id = seed_product(&pool).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_customer_mapping(tenant, InvoiceProviderKind::Quickbooks, company_id, "58")
        .await
        .expect("map the company to a QuickBooks customer");
    mappings
        .upsert_product_mapping(tenant, InvoiceProviderKind::Quickbooks, product_id, "14")
        .await
        .expect("map the product to a QuickBooks item");

    let mut body = request(company_id);
    body.lines[0].product_id = Some(product_id);
    let created = billing
        .create_invoice(tenant, &body, &AuditCtx::system(common::DEFAULT_TENANT_ID))
        .await
        .expect("create the invoice");

    assert_eq!(stub.lock().unwrap().issue.len(), 1);
    let columns = external_columns(&pool, created.id)
        .await
        .expect("the row exists");
    assert_eq!(columns.0.as_deref(), Some("quickbooks"));
    assert_eq!(columns.1.as_deref(), Some("1042"));
    assert_eq!(columns.2.as_deref(), Some("1042"));
}

/// QuickBooks refuses a line with no product, and says so before
/// anything local is written.
///
/// Not a quirk of the fixture: QBO's invoice lines carry an `ItemRef`
/// into the company's own item list, so a free-text line has nothing to
/// point at. The refusal is the client being honest about its provider
/// rather than inventing an item, and the message has to reach whoever
/// wrote the invoice.
#[mokosh_test]
async fn quickbooks_refuses_a_line_that_names_no_product(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, common::DEFAULT_TENANT_ID, "quickbooks").await;
    seed_quickbooks_blob(&secrets, common::DEFAULT_TENANT_ID).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_customer_mapping(tenant, InvoiceProviderKind::Quickbooks, company_id, "58")
        .await
        .expect("map the company");

    let err = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect_err("a free-text line has no QuickBooks item to point at");
    assert!(
        err.to_string().contains("product"),
        "the message has to name what is missing: {err}"
    );
    assert_eq!(stub.lock().unwrap().issue.len(), 0);
    assert_eq!(invoice_count(&pool).await, 0, "and no row is written");
}

/// The flag off is the state of every deployment today: no provider is
/// reached, and the row is the local one it has always been.
#[mokosh_test]
async fn the_flag_off_reaches_no_provider_at_all(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, false).await;

    // Everything a delegated tenant has, except the toggle.
    delegate(&pool, common::DEFAULT_TENANT_ID, "xero").await;
    seed_xero_blob(&secrets, common::DEFAULT_TENANT_ID, 55).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_customer_mapping(
            tenant,
            InvoiceProviderKind::Xero,
            company_id,
            "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e",
        )
        .await
        .expect("map the company");

    let created = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the invoice");

    assert_eq!(
        stub.lock().unwrap().issue.len(),
        0,
        "the toggle gates the whole path, delegation or not"
    );
    let columns = external_columns(&pool, created.id)
        .await
        .expect("the row exists");
    assert_eq!(
        (columns.0, columns.1, columns.2),
        (None, None, None),
        "a local invoice names no external provider"
    );
}

/// MAPPS-1145: a disconnected provider takes the local path, and does not
/// fail.
///
/// The capability survives a disconnect on purpose, so this row says
/// `invoicing` is delegated and holds no credential. `plan` used to read
/// the capability alone, which would send this invoice to the provider and
/// refuse it `Unauthorized` on a blob that is gone - every invoice create
/// for the tenant failing, with a row that says `disconnected` as the only
/// clue.
#[mokosh_test]
async fn a_disconnected_provider_falls_back_to_the_local_path(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    // The exact state a disconnect leaves: capability kept, status
    // disconnected, and no credential at all.
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, enabled_capabilities, \
             disconnected_at) \
         VALUES ($1, 'xero', 'disconnected', ARRAY['invoicing']::text[], NOW())",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed a disconnected row");
    InvoiceIssuerMappingService::new(db)
        .upsert_customer_mapping(
            tenant,
            InvoiceProviderKind::Xero,
            company_id,
            "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e",
        )
        .await
        .expect("map the company");
    assert!(
        secrets
            .get(&mokosh_server::secrets::SecretKey::integration(
                common::DEFAULT_TENANT_ID,
                "xero"
            ))
            .await
            .expect("read")
            .is_none(),
        "the fixture holds no credential, which is what a disconnect leaves"
    );

    let created = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("a disconnected provider must not break invoicing");

    assert_eq!(stub.lock().unwrap().issue.len(), 0, "nothing is sent");
    let columns = external_columns(&pool, created.id)
        .await
        .expect("the row exists");
    assert_eq!(
        (columns.0, columns.1, columns.2),
        (None, None, None),
        "and the invoice is Mokosh's own"
    );
}

/// The toggle on, and nothing delegated: still the local path.
#[mokosh_test]
async fn a_tenant_that_delegated_nothing_keeps_the_local_path(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let (billing, _db, _secrets) = service_with_dispatch(&pool, &base, true).await;

    let created = billing
        .create_invoice(
            tenant,
            &request(company_id),
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the invoice");

    assert_eq!(stub.lock().unwrap().issue.len(), 0);
    let columns = external_columns(&pool, created.id)
        .await
        .expect("the row exists");
    assert_eq!((columns.0, columns.1, columns.2), (None, None, None));
}
