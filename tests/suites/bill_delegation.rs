//! MAPPS-1155: `create_bill` through the delegated issuer, end to end.
//!
//! The bill half of `invoice_issuer_delegation`, and the same harness: the
//! two provider clients point at an axum stub on `127.0.0.1:0`, every
//! dependency of `IssuerDispatcher::new` is injected, and the cases assert
//! on what the provider was ASKED as well as on what the local row ends up
//! holding.
//!
//! What only an integration test can show here: that the push happens
//! BEFORE the write transaction opens, so a provider that refuses leaves no
//! `bills` row behind; that a deployment with `Feature::DelegatedBills` off
//! reaches no provider at all; and that the two refusals a reader is most
//! likely to hit in practice (an unmapped vendor, an unmapped expense
//! category) name the route that fixes them instead of failing inside a
//! provider call.

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
use mokosh_server::modules::billing::provider_invoice::{QuickBooksClient, XeroClient};
use mokosh_server::modules::expenses::service::{
    BillLineInput, CreateBillRequest, ExpensesService, UpsertExpenseCategoryRequest,
    UpsertVendorRequest,
};
use mokosh_server::modules::features::{Feature, FeatureSnapshot, FeatureToggles};
use mokosh_server::modules::integrations::IntegrationsService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
use mokosh_server::utils::error::AppError;
use mokosh_test::mokosh_test;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// A Xero contact id and a QuickBooks vendor id, as the mappings hold
/// them. Xero parses its own as a UUID; QuickBooks' is numeric-as-text.
const XERO_CONTACT: &str = "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e";
const QBO_VENDOR: &str = "56";
const QBO_ACCOUNT: &str = "7";

/// What a stub provider was asked for, and what it answers.
///
/// Counting the calls is half the point: the flag-off and not-delegated
/// cases are only convincing if the provider was never reached, and "the
/// columns are NULL" alone would also be true of a call that happened and
/// was ignored.
#[derive(Default)]
struct Calls {
    bills: Vec<Value>,
    refuse_with: Option<StatusCode>,
}

type Stub = Arc<Mutex<Calls>>;

async fn xero_bill(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.bills.push(body);
    if let Some(status) = calls.refuse_with {
        return (status, Json(json!({ "Message": "the provider refused" })));
    }
    (
        StatusCode::OK,
        Json(json!({
            "Invoices": [{
                "InvoiceID": "0b9b3e1a-5c7d-4a2f-8e6b-1d3f5a7c9e11",
                "InvoiceNumber": "BILL-0007",
                "Status": "AUTHORISED",
            }]
        })),
    )
}

async fn quickbooks_bill(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.bills.push(body);
    if let Some(status) = calls.refuse_with {
        return (
            status,
            Json(json!({ "Fault": { "type": "ValidationFault" } })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "Bill": { "Id": "981", "SyncToken": "0" } })),
    )
}

async fn token() -> impl IntoResponse {
    Json(json!({
        "access_token": "refreshed-access",
        "refresh_token": "rotated-refresh",
        "expires_in": 1800,
        "x_refresh_token_expires_in": 8_640_000,
        "token_type": "Bearer",
    }))
}

/// One stub serving both providers, since a case only ever delegates to
/// one of them and the paths do not collide.
async fn start_stub() -> (Stub, String) {
    let stub: Stub = Arc::new(Mutex::new(Calls::default()));
    let app = axum::Router::new()
        .route("/api.xro/2.0/Invoices", axum::routing::post(xero_bill))
        .route(
            "/v3/company/{realm}/bill",
            axum::routing::post(quickbooks_bill),
        )
        .route("/connect/token", axum::routing::post(token))
        .route("/oauth2/v1/tokens/bearer", axum::routing::post(token))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (stub, base)
}

/// An `ExpensesService` wired as `create_api_router` wires the serving
/// one, except that the two clients point at the stub.
async fn service_with_dispatch(
    pool: &PgPool,
    base: &str,
    flag_on: bool,
) -> (ExpensesService, Database, Arc<dyn SecretProvider>) {
    let app_pool = common::build_app_role_pool(pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let toggles = if flag_on {
        FeatureToggles::from_rows([(Feature::DelegatedBills.key(), true)])
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
    let expenses = ExpensesService::new(db.clone()).with_bill_dispatch(Arc::new(dispatcher));
    (expenses, db, secrets)
}

/// The deployment's applications, as a fixture supplies them (MAPPS-1139:
/// the client id and secret are the HOST's, so they come from here rather
/// than from a tenant's blob).
fn fixture_apps() -> mokosh_server::modules::billing::invoice_issuer_app::IssuerApps {
    use mokosh_server::modules::billing::invoice_issuer_app::{IssuerApp, IssuerApps};
    let app = || {
        Some(IssuerApp {
            client_id: "fixture-app".to_string(),
            client_secret: "fixture-only-not-a-credential".to_string(),
            webhook_key: None,
        })
    };
    IssuerApps {
        xero: app(),
        quickbooks: app(),
    }
}

/// Connect one provider on this tenant with the capabilities named, the
/// way the integrations surface does.
async fn connect(pool: &PgPool, provider: &str, capabilities: &[&str]) {
    let caps: Vec<String> = capabilities.iter().map(|c| c.to_string()).collect();
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, enabled_capabilities) \
         VALUES ($1, $2, 'connected', $3) \
         ON CONFLICT (tenant_id, provider) DO UPDATE \
           SET status = 'connected', enabled_capabilities = EXCLUDED.enabled_capabilities",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .bind(&caps)
    .execute(pool)
    .await
    .expect("connect the provider");
}

/// The stored OAuth state the dispatcher reads, built from the production
/// types and written with the production serialiser rather than a `json!`
/// literal: the fixture cannot drift from the shape the code parses, and a
/// literal carrying `client_id` / `refresh_token` is the GCP
/// authorized-user credential shape the secrets scan flags on sight.
async fn seed_xero_blob(secrets: &Arc<dyn SecretProvider>) {
    let blob = IntegrationCredentialBlob::Xero(XeroBlob {
        refresh_token: "fixture-rotating-value".to_string(),
        access_token: "fixture-bearer".to_string(),
        access_token_expires_at: Utc::now() + Duration::minutes(55),
        tenant_id: "xero-org-1".to_string(),
    });
    secrets
        .put(
            &SecretKey::integration(common::DEFAULT_TENANT_ID, "xero"),
            &serialize_blob(&blob).expect("serialise the blob"),
        )
        .await
        .expect("seed the xero credential blob");
}

async fn seed_quickbooks_blob(secrets: &Arc<dyn SecretProvider>) {
    let blob = IntegrationCredentialBlob::Quickbooks(QuickbooksBlob {
        refresh_token: "fixture-rotating-value".to_string(),
        access_token: "fixture-bearer".to_string(),
        access_token_expires_at: Utc::now() + Duration::minutes(55),
        realm_id: "4620816365".to_string(),
        refresh_token_expires_at: Some(Utc::now() + Duration::days(90)),
    });
    secrets
        .put(
            &SecretKey::integration(common::DEFAULT_TENANT_ID, "quickbooks"),
            &serialize_blob(&blob).expect("serialise the blob"),
        )
        .await
        .expect("seed the quickbooks credential blob");
}

fn ctx() -> AuditCtx {
    AuditCtx::system(common::DEFAULT_TENANT_ID)
}

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

/// Two lines, 1.00 x 50.00 and 2.00 x 10.00: 70.00 subtotal, so the
/// per-line amounts a provider is sent are 50.00 and 20.00.
fn bill_body(vendor_id: Uuid, category_id: Option<Uuid>) -> CreateBillRequest {
    CreateBillRequest {
        vendor_id,
        bill_number: Some("VEN-7781".to_string()),
        issue_date: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
        due_date: Some(NaiveDate::from_ymd_opt(2026, 11, 23).unwrap()),
        currency: "USD".to_string(),
        notes: None,
        lines: vec![
            BillLineInput {
                category_id,
                description: "Rack space".to_string(),
                quantity_hundredths: 100,
                unit_price_minor: 50_00,
                tax_minor: 0,
                position: 0,
            },
            BillLineInput {
                category_id,
                description: "Cross connects".to_string(),
                quantity_hundredths: 200,
                unit_price_minor: 10_00,
                tax_minor: 0,
                position: 1,
            },
        ],
    }
}

async fn seed_vendor(svc: &ExpensesService) -> Uuid {
    svc.create_vendor(
        tenant(),
        &UpsertVendorRequest {
            name: "Rack Co".to_string(),
            account_number: None,
            default_currency: Some("USD".to_string()),
            notes: None,
        },
        &ctx(),
    )
    .await
    .expect("seed a vendor")
    .id
}

async fn seed_category(svc: &ExpensesService) -> Uuid {
    svc.create_expense_category(
        tenant(),
        &UpsertExpenseCategoryRequest {
            name: "Colocation".to_string(),
            is_active: true,
        },
        &ctx(),
    )
    .await
    .expect("seed a category")
    .id
}

/// The two external columns on a bill row, or `None` when no row exists.
async fn external_columns(pool: &PgPool, id: Uuid) -> Option<(Option<String>, Option<String>)> {
    sqlx::query_as("SELECT external_provider, external_bill_id FROM bills WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("read the bill row")
}

async fn bill_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM bills")
        .fetch_one(pool)
        .await
        .expect("count bills")
}

/// A tenant that delegated Bills and expenses to Xero has the bill raised
/// there as an ACCPAY, and the local row records who holds it.
#[mokosh_test]
async fn a_delegated_tenant_has_the_bill_raised_in_xero(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let vendor_id = seed_vendor(&svc).await;

    connect(&pool, "xero", &["bills_and_expenses"]).await;
    seed_xero_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_vendor_mapping(tenant(), InvoiceProviderKind::Xero, vendor_id, XERO_CONTACT)
        .await
        .expect("map the vendor to a Xero contact");

    let created = svc
        .create_bill(tenant(), &bill_body(vendor_id, None), &ctx())
        .await
        .expect("create the bill");

    // Copied out rather than asserted under the guard: `drop(calls)` before
    // the next await is not enough for `clippy::await_holding_lock`, which
    // reads the binding's scope and not the drop.
    let (raised, sent) = {
        let calls = stub.lock().unwrap();
        (calls.bills.len(), calls.bills.first().cloned())
    };
    let sent = sent.expect("Xero was asked");
    assert_eq!(raised, 1, "Xero is asked exactly once");
    assert_eq!(
        sent["Type"], "ACCPAY",
        "a bill is a payable, not a receivable: {sent}"
    );
    assert_eq!(sent["Contact"]["ContactID"], XERO_CONTACT);
    assert_eq!(sent["CurrencyCode"], "USD");
    assert_eq!(sent["Date"], "2026-10-23");
    assert_eq!(sent["DueDate"], "2026-11-23");
    assert_eq!(sent["LineItems"][0]["Description"], "Rack space");
    assert_eq!(sent["LineItems"][0]["UnitAmount"], "50.00");
    assert_eq!(sent["LineItems"][1]["Quantity"], "2.00");

    let columns = external_columns(&pool, created.bill.id)
        .await
        .expect("the row exists");
    assert_eq!(columns.0.as_deref(), Some("xero"));
    assert_eq!(
        columns.1.as_deref(),
        Some("0b9b3e1a-5c7d-4a2f-8e6b-1d3f5a7c9e11"),
        "the provider's own id is what a reconciliation reads back"
    );
    assert_eq!(
        created.bill.status, "draft",
        "delegation does not approve the bill: approval is the MSP's own step"
    );
    assert_eq!(created.lines.len(), 2, "and the local lines are still kept");
    assert_eq!(created.bill.total_minor, 70_00);
}

/// The switch off is the untouched local path: no provider call, and both
/// external columns NULL on a row that is otherwise what it always was.
#[mokosh_test]
async fn the_switch_off_leaves_the_local_path_alone(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, false).await;
    let vendor_id = seed_vendor(&svc).await;

    // Everything a delegated tenant has: connected, capability enabled,
    // credentials seeded, vendor mapped. Only the deployment switch is off.
    connect(&pool, "xero", &["bills_and_expenses"]).await;
    seed_xero_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_vendor_mapping(tenant(), InvoiceProviderKind::Xero, vendor_id, XERO_CONTACT)
        .await
        .expect("map the vendor");

    let created = svc
        .create_bill(tenant(), &bill_body(vendor_id, None), &ctx())
        .await
        .expect("create the bill");

    assert_eq!(
        stub.lock().unwrap().bills.len(),
        0,
        "the flag is off: no provider is reached at all"
    );
    let columns = external_columns(&pool, created.bill.id)
        .await
        .expect("the row exists");
    assert_eq!(columns.0, None, "external_provider stays NULL");
    assert_eq!(columns.1, None, "external_bill_id stays NULL");
    assert_eq!(created.bill.total_minor, 70_00);
}

/// Connected but without the capability is the local path too: a tenant
/// that uses Xero for invoicing only does not get its bills pushed.
#[mokosh_test]
async fn a_provider_without_the_capability_is_not_asked(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let vendor_id = seed_vendor(&svc).await;

    connect(&pool, "xero", &["invoicing"]).await;
    seed_xero_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_vendor_mapping(tenant(), InvoiceProviderKind::Xero, vendor_id, XERO_CONTACT)
        .await
        .expect("map the vendor");

    let created = svc
        .create_bill(tenant(), &bill_body(vendor_id, None), &ctx())
        .await
        .expect("create the bill");

    assert_eq!(
        stub.lock().unwrap().bills.len(),
        0,
        "Invoicing is not Bills and expenses"
    );
    assert_eq!(
        external_columns(&pool, created.bill.id).await,
        Some((None, None)),
        "the row is the local one"
    );
}

/// An unmapped vendor is refused by name, before anything local is
/// written: no bill row, and the message names the route that fixes it.
#[mokosh_test]
async fn an_unmapped_vendor_is_refused_and_writes_no_row(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, _db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let vendor_id = seed_vendor(&svc).await;

    connect(&pool, "xero", &["bills_and_expenses"]).await;
    seed_xero_blob(&secrets).await;

    let err = svc
        .create_bill(tenant(), &bill_body(vendor_id, None), &ctx())
        .await
        .expect_err("an unmapped vendor cannot be delegated");

    let AppError::Conflict(message) = &err else {
        panic!("a client-stated conflict is not a server fault: {err:?}");
    };
    assert!(
        message.contains("invoice-issuer-mappings/vendors/xero"),
        "the refusal names the route that fixes it: {message}"
    );
    assert_eq!(
        stub.lock().unwrap().bills.len(),
        0,
        "and Xero was never asked"
    );
    assert_eq!(bill_count(&pool).await, 0, "no half-created bill is left");
}

/// A provider that refuses leaves no local row: the push happens before
/// the write transaction opens, which is the whole reason it is ordered
/// that way.
#[mokosh_test]
async fn a_refusing_provider_leaves_no_bill_behind(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let vendor_id = seed_vendor(&svc).await;

    connect(&pool, "xero", &["bills_and_expenses"]).await;
    seed_xero_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_vendor_mapping(tenant(), InvoiceProviderKind::Xero, vendor_id, XERO_CONTACT)
        .await
        .expect("map the vendor");
    stub.lock().unwrap().refuse_with = Some(StatusCode::BAD_REQUEST);

    let err = svc
        .create_bill(tenant(), &bill_body(vendor_id, None), &ctx())
        .await
        .expect_err("the provider refused");

    assert!(
        !stub.lock().unwrap().bills.is_empty(),
        "the provider WAS asked: {err:?}"
    );
    assert_eq!(
        bill_count(&pool).await,
        0,
        "and nothing local was written for a bill the provider does not have"
    );
}

/// QuickBooks takes a bill against a vendor with an account-based line,
/// and the account comes from the expense category's mapping.
#[mokosh_test]
async fn a_delegated_quickbooks_bill_posts_to_the_mapped_account(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let vendor_id = seed_vendor(&svc).await;
    let category_id = seed_category(&svc).await;

    connect(&pool, "quickbooks", &["bills_and_expenses"]).await;
    seed_quickbooks_blob(&secrets).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_vendor_mapping(
            tenant(),
            InvoiceProviderKind::Quickbooks,
            vendor_id,
            QBO_VENDOR,
        )
        .await
        .expect("map the vendor");
    mappings
        .upsert_expense_account_mapping(
            tenant(),
            InvoiceProviderKind::Quickbooks,
            category_id,
            QBO_ACCOUNT,
        )
        .await
        .expect("map the category to an account");

    let created = svc
        .create_bill(tenant(), &bill_body(vendor_id, Some(category_id)), &ctx())
        .await
        .expect("create the bill");

    let sent = {
        let calls = stub.lock().unwrap();
        assert_eq!(calls.bills.len(), 1, "QuickBooks is asked exactly once");
        calls.bills[0].clone()
    };
    assert_eq!(sent["VendorRef"]["value"], QBO_VENDOR);
    assert_eq!(sent["CurrencyRef"]["value"], "USD");
    assert_eq!(sent["TxnDate"], "2026-10-23");
    assert_eq!(sent["DueDate"], "2026-11-23");
    assert_eq!(
        sent["Line"][0]["DetailType"], "AccountBasedExpenseLineDetail",
        "a bill line is an expense against an account: {sent}"
    );
    assert_eq!(
        sent["Line"][0]["AccountBasedExpenseLineDetail"]["AccountRef"]["value"],
        QBO_ACCOUNT
    );
    assert_eq!(
        sent["Line"][0]["Amount"], "50.00",
        "the amount is the line total, not the unit price"
    );
    assert_eq!(sent["Line"][1]["Amount"], "20.00");

    let columns = external_columns(&pool, created.bill.id)
        .await
        .expect("the row exists");
    assert_eq!(columns.0.as_deref(), Some("quickbooks"));
    assert_eq!(columns.1.as_deref(), Some("981"));
}

/// A QuickBooks bill whose line has no mapped account is refused by name:
/// guessing the account would file the MSP's costs in the wrong place in
/// their own ledger.
#[mokosh_test]
async fn an_unmapped_expense_category_is_refused_for_quickbooks(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let vendor_id = seed_vendor(&svc).await;
    let category_id = seed_category(&svc).await;

    connect(&pool, "quickbooks", &["bills_and_expenses"]).await;
    seed_quickbooks_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_vendor_mapping(
            tenant(),
            InvoiceProviderKind::Quickbooks,
            vendor_id,
            QBO_VENDOR,
        )
        .await
        .expect("map the vendor");

    let err = svc
        .create_bill(tenant(), &bill_body(vendor_id, Some(category_id)), &ctx())
        .await
        .expect_err("an unmapped category cannot be delegated to QuickBooks");

    let AppError::Conflict(message) = &err else {
        panic!("a client-stated conflict is not a server fault: {err:?}");
    };
    assert!(
        message.contains("expense-accounts/quickbooks"),
        "the refusal names the route that fixes it: {message}"
    );
    assert_eq!(stub.lock().unwrap().bills.len(), 0, "nothing was sent");
    assert_eq!(bill_count(&pool).await, 0, "and no local row was written");
}

/// A categoryless line is refused for QuickBooks before any mapping is
/// read: Mokosh allows the line, QuickBooks does not, and the message says
/// which line.
#[mokosh_test]
async fn a_categoryless_line_is_refused_for_quickbooks(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let vendor_id = seed_vendor(&svc).await;

    connect(&pool, "quickbooks", &["bills_and_expenses"]).await;
    seed_quickbooks_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_vendor_mapping(
            tenant(),
            InvoiceProviderKind::Quickbooks,
            vendor_id,
            QBO_VENDOR,
        )
        .await
        .expect("map the vendor");

    let err = svc
        .create_bill(tenant(), &bill_body(vendor_id, None), &ctx())
        .await
        .expect_err("a QuickBooks bill line needs an account");

    let AppError::Conflict(message) = &err else {
        panic!("a client-stated conflict is not a server fault: {err:?}");
    };
    assert!(
        message.contains("Rack space"),
        "the refusal names the line: {message}"
    );
    assert_eq!(stub.lock().unwrap().bills.len(), 0, "nothing was sent");
    assert_eq!(bill_count(&pool).await, 0, "and no local row was written");
}
