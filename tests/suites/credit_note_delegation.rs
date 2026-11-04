//! PMS-1546: crediting an invoice the provider issued, end to end.
//!
//! A credit note corrects a document the customer holds, and for a
//! delegated invoice the document they hold is Xero's or QuickBooks's.
//! Before this, `create_credit_note` had no provider path at all: the two
//! ledgers came apart by exactly the credited amount and the provider
//! kept showing the customer the balance the credit had just corrected.
//!
//! What only an integration test can show here: that the credit document
//! and its application are two calls with different consequences (a
//! refused creation leaves no local row, a refused application keeps
//! both halves and says so), that voiding takes the provider's copy with
//! it, and that a credit note against a locally-issued invoice reaches no
//! provider at all.

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
    CreateCreditNoteLineRequest, CreateCreditNoteRequest, CreateInvoiceLineRequest,
    CreateInvoiceRequest, InvoiceLineType,
};
use mokosh_server::modules::billing::provider_invoice::{QuickBooksClient, XeroClient};
use mokosh_server::modules::billing::service::BillingService;
use mokosh_server::modules::features::{Feature, FeatureSnapshot, FeatureToggles};
use mokosh_server::modules::integrations::IntegrationsService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
use mokosh_test::mokosh_test;
use mokosh_types::billing::CreditNoteStatus;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// The Xero contact and invoice ids the stub answers with, and the
/// QuickBooks customer the mapping points at.
const XERO_CONTACT: &str = "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e";
const XERO_INVOICE: &str = "9f1d1c62-0f3a-4a1e-9c6f-7b2c9d4e5a60";
const XERO_CREDIT_NOTE: &str = "2c7b4e51-8a6d-4f2b-9c1e-5d3a7f8b9c01";
const XERO_ALLOCATION: &str = "7a51c0de-3f2b-4e8a-9d6c-1b2a3f4e5d60";
const QBO_CUSTOMER: &str = "58";
const QBO_CREDIT_MEMO: &str = "88";

/// What each stub endpoint was asked for, and what it answers.
#[derive(Default)]
struct Calls {
    /// Invoice creations, which every case needs to get a delegated
    /// invoice to credit.
    invoices: Vec<Value>,
    /// The credit documents the provider was asked to raise.
    credits: Vec<Value>,
    /// The applications: Xero's allocation bodies and QuickBooks's
    /// zero-total payments, in one list because each provider sends
    /// exactly one and the case knows which it asked for.
    applications: Vec<Value>,
    /// Voids of a credit document, as `(id, body)`.
    credit_voids: Vec<(String, Value)>,
    /// Allocations taken off a Xero credit note before it is voided, as
    /// `(credit_note_id, allocation_id)`.
    unallocations: Vec<(String, String)>,
    /// When set, raising the credit document answers this status.
    credit_refuses_with: Option<StatusCode>,
    /// When set, applying it answers this status.
    application_refuses_with: Option<StatusCode>,
    /// What Xero says the credit note's status is, which decides
    /// `Voided` against `AlreadyVoided`.
    xero_credit_status: String,
    /// Whether the Xero credit note still carries an allocation when the
    /// void reads it.
    xero_credit_allocated: bool,
}

type Stub = Arc<Mutex<Calls>>;

async fn xero_issue(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    stub.lock().unwrap().invoices.push(body);
    (
        StatusCode::OK,
        Json(json!({
            "Invoices": [{
                "InvoiceID": XERO_INVOICE,
                "InvoiceNumber": "INV-0042",
                "Status": "AUTHORISED",
            }]
        })),
    )
}

/// `POST /CreditNotes`: Xero raises the credit document.
async fn xero_credit_note(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.credits.push(body);
    if let Some(status) = calls.credit_refuses_with {
        return (
            status,
            Json(json!({ "Message": "Xero refused the credit note" })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "CreditNotes": [{
                "CreditNoteID": XERO_CREDIT_NOTE,
                "CreditNoteNumber": "CN-0005",
                "Type": "ACCRECCREDIT",
                "Status": "AUTHORISED",
            }]
        })),
    )
}

/// `PUT /CreditNotes/{id}/Allocations`: Xero applies it to the invoice.
async fn xero_allocate(
    State(stub): State<Stub>,
    axum::extract::Path(_id): axum::extract::Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.applications.push(body);
    if let Some(status) = calls.application_refuses_with {
        return (
            status,
            Json(json!({
                "Message": "The credit note has no remaining credit to allocate"
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "Allocations": [{ "Amount": 40.0 }] })),
    )
}

/// `GET /CreditNotes/{id}`: what Xero says the credit note is now, which
/// is what the void reads before it writes.
async fn xero_credit_note_read(
    State(stub): State<Stub>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let (status, allocated) = {
        let calls = stub.lock().unwrap();
        (
            calls.xero_credit_status.clone(),
            calls.xero_credit_allocated,
        )
    };
    let allocations = if allocated {
        json!([{ "AllocationID": XERO_ALLOCATION, "Amount": 40.0 }])
    } else {
        json!([])
    };
    Json(json!({
        "CreditNotes": [{
            "CreditNoteID": id,
            "CreditNoteNumber": "CN-0005",
            "Type": "ACCRECCREDIT",
            "Status": status,
            "Allocations": allocations,
        }]
    }))
}

/// `POST /CreditNotes/{id}` carrying `{"Status": "VOIDED"}`.
async fn xero_credit_note_void(
    State(stub): State<Stub>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    stub.lock().unwrap().credit_voids.push((id.clone(), body));
    Json(json!({
        "CreditNotes": [{
            "CreditNoteID": id,
            "Type": "ACCRECCREDIT",
            "Status": "VOIDED",
        }]
    }))
}

/// `DELETE /CreditNotes/{id}/Allocations/{allocation_id}`.
async fn xero_unallocate(
    State(stub): State<Stub>,
    axum::extract::Path((credit_note_id, allocation_id)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    stub.lock()
        .unwrap()
        .unallocations
        .push((credit_note_id, allocation_id.clone()));
    Json(json!({ "AllocationId": allocation_id, "IsDeleted": true }))
}

async fn quickbooks_issue(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    stub.lock().unwrap().invoices.push(body);
    (
        StatusCode::OK,
        Json(json!({ "Invoice": { "Id": "1042", "DocNumber": "1042", "SyncToken": "0" } })),
    )
}

/// `POST /creditmemo`: raise the credit, or void it when the query says
/// so, which is how Intuit splits the two on one collection URL.
async fn quickbooks_credit_memo(
    State(stub): State<Stub>,
    uri: axum::http::Uri,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let mut calls = stub.lock().unwrap();
    if uri.query().unwrap_or_default().contains("operation=void") {
        let id = body["Id"].as_str().unwrap_or_default().to_string();
        calls.credit_voids.push((id, body));
        return Json(json!({
            "CreditMemo": { "Id": QBO_CREDIT_MEMO, "SyncToken": "2", "PrivateNote": "Voided" }
        }))
        .into_response();
    }
    calls.credits.push(body);
    if let Some(status) = calls.credit_refuses_with {
        return (
            status,
            Json(json!({ "Fault": { "type": "ValidationFault" } })),
        )
            .into_response();
    }
    Json(json!({
        "CreditMemo": { "Id": QBO_CREDIT_MEMO, "DocNumber": "1009", "SyncToken": "0" }
    }))
    .into_response()
}

/// `GET /creditmemo/{id}`: the read a void needs for the `SyncToken`.
async fn quickbooks_credit_memo_read(State(stub): State<Stub>) -> impl IntoResponse {
    let voided = stub
        .lock()
        .unwrap()
        .xero_credit_status
        .eq_ignore_ascii_case("VOIDED");
    Json(json!({
        "CreditMemo": {
            "Id": QBO_CREDIT_MEMO,
            "SyncToken": "1",
            "PrivateNote": if voided { "Voided" } else { "" },
        }
    }))
}

/// `POST /payment`: the zero-total payment that applies a credit memo.
async fn quickbooks_payment(
    State(stub): State<Stub>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.applications.push(body);
    if let Some(status) = calls.application_refuses_with {
        return (
            status,
            Json(json!({ "Fault": { "type": "ValidationFault" } })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "Payment": { "Id": "301", "TotalAmt": 0 } })),
    )
}

async fn token() -> impl IntoResponse {
    Json(json!({
        "access_token": "fixture-bearer",
        "refresh_token": "fixture-rotating-value",
        "expires_in": 1800,
        "token_type": "Bearer",
    }))
}

async fn start_stub() -> (Stub, String) {
    let stub: Stub = Arc::new(Mutex::new(Calls {
        xero_credit_status: "AUTHORISED".to_string(),
        xero_credit_allocated: true,
        ..Calls::default()
    }));
    let app = axum::Router::new()
        .route("/api.xro/2.0/Invoices", axum::routing::post(xero_issue))
        .route(
            "/api.xro/2.0/CreditNotes",
            axum::routing::post(xero_credit_note),
        )
        // The read and the void share the credit note's own URL, exactly
        // as they do for an invoice.
        .route(
            "/api.xro/2.0/CreditNotes/{id}",
            axum::routing::get(xero_credit_note_read).post(xero_credit_note_void),
        )
        .route(
            "/api.xro/2.0/CreditNotes/{id}/Allocations",
            axum::routing::put(xero_allocate),
        )
        .route(
            "/api.xro/2.0/CreditNotes/{id}/Allocations/{allocation_id}",
            axum::routing::delete(xero_unallocate),
        )
        .route(
            "/v3/company/{realm}/invoice",
            axum::routing::post(quickbooks_issue),
        )
        .route(
            "/v3/company/{realm}/creditmemo",
            axum::routing::post(quickbooks_credit_memo),
        )
        .route(
            "/v3/company/{realm}/creditmemo/{id}",
            axum::routing::get(quickbooks_credit_memo_read),
        )
        .route(
            "/v3/company/{realm}/payment",
            axum::routing::post(quickbooks_payment),
        )
        .route("/connect/token", axum::routing::post(token))
        .route("/oauth2/v1/tokens/bearer", axum::routing::post(token))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (stub, base)
}

/// A `BillingService` wired as `create_api_router` wires the serving one,
/// with both clients pointed at the stub.
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

async fn delegate(pool: &PgPool, provider: &str) {
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, enabled_capabilities) \
         VALUES ($1, $2, 'connected', ARRAY['invoicing']::text[]) \
         ON CONFLICT (tenant_id, provider) DO UPDATE \
           SET status = 'connected', enabled_capabilities = EXCLUDED.enabled_capabilities",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .execute(pool)
    .await
    .expect("delegate invoicing");
}

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

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

fn ctx() -> AuditCtx {
    AuditCtx::system(common::DEFAULT_TENANT_ID)
}

fn invoice_request(company_id: Uuid, product_id: Option<Uuid>) -> CreateInvoiceRequest {
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
            product_id,
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

/// A credit for 40 against `invoice_id`, naming `product_id` when the
/// provider needs one.
fn credit_request(invoice_id: Uuid, product_id: Option<Uuid>) -> CreateCreditNoteRequest {
    CreateCreditNoteRequest {
        invoice_id,
        issue_date: Some(NaiveDate::from_ymd_opt(2026, 10, 28).unwrap()),
        reason: "Billed for a site already decommissioned".to_string(),
        tax_amount: None,
        currency: Some("USD".to_string()),
        notes: None,
        lines: vec![CreateCreditNoteLineRequest {
            line_type: InvoiceLineType::Service,
            product_id,
            description: "Decommissioned site, October".to_string(),
            quantity: Decimal::ONE,
            unit_price: Decimal::from(40),
            sort_order: 0,
        }],
    }
}

/// A send that attests to a delivery made outside Mokosh: these cases
/// are about the provider calls, not the mail.
fn send_request() -> mokosh_server::modules::billing::models::UpdateInvoiceRequest {
    use mokosh_server::modules::billing::models::{
        DeliveryMethod, DeliveryRequest, InvoiceStatus, UpdateInvoiceRequest,
    };
    UpdateInvoiceRequest {
        company_id: None,
        billing_contact_id: None,
        contract_id: None,
        invoice_date: None,
        due_date: None,
        payment_terms: None,
        payment_term_id: None,
        tax_amount: None,
        tax_rate_id: None,
        discount_amount: None,
        notes: None,
        po_number: None,
        lines: None,
        status: Some(InvoiceStatus::Sent),
        delivery: Some(DeliveryRequest {
            method: DeliveryMethod::Other,
            note: Some("Delivered outside Mokosh for this test".to_string()),
        }),
        legacy_skip_email: None,
    }
}

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

/// The three external columns on a credit note row.
async fn credit_note_columns(
    pool: &PgPool,
    id: Uuid,
) -> Option<(Option<String>, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT external_provider, external_credit_note_id, external_number \
         FROM credit_notes WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .expect("read the credit note row")
}

async fn credit_note_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM credit_notes")
        .fetch_one(pool)
        .await
        .expect("count credit notes")
}

async fn amount_credited(pool: &PgPool, invoice_id: Uuid) -> Decimal {
    sqlx::query_scalar("SELECT amount_credited FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(pool)
        .await
        .expect("read the credited total")
}

/// A delegated invoice, issued by `provider`, ready to be credited.
async fn delegated_invoice(
    billing: &BillingService,
    pool: &PgPool,
    db: Database,
    provider: InvoiceProviderKind,
    external_customer: &str,
) -> (Uuid, Option<Uuid>) {
    let company_id = common::seed_company(pool).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_customer_mapping(tenant(), provider, company_id, external_customer)
        .await
        .expect("map the company");
    // QuickBooks refuses a sales line that names no item, on an invoice
    // and on a credit memo alike, so that path needs a product and its
    // mapping; Xero takes a description at a price.
    let product_id = if provider == InvoiceProviderKind::Quickbooks {
        let product_id = seed_product(pool).await;
        mappings
            .upsert_product_mapping(tenant(), provider, product_id, "item-9")
            .await
            .expect("map the product");
        Some(product_id)
    } else {
        None
    };
    let invoice = billing
        .create_invoice(tenant(), &invoice_request(company_id, product_id), &ctx())
        .await
        .expect("create the invoice");
    (invoice.id, product_id)
}

/// Crediting a Xero-issued invoice raises the credit note there and
/// applies it to the invoice the customer holds.
#[mokosh_test]
async fn crediting_a_xero_invoice_raises_the_credit_note_and_applies_it(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "xero").await;
    seed_xero_blob(&secrets).await;
    let (invoice_id, _product) =
        delegated_invoice(&billing, &pool, db, InvoiceProviderKind::Xero, XERO_CONTACT).await;

    let note = billing
        .create_credit_note(tenant(), "UTC", &credit_request(invoice_id, None), &ctx())
        .await
        .expect("credit the invoice");

    let (credit, application) = {
        let calls = stub.lock().unwrap();
        assert_eq!(calls.credits.len(), 1, "Xero is asked exactly once");
        assert_eq!(calls.applications.len(), 1, "and applies it exactly once");
        (calls.credits[0].clone(), calls.applications[0].clone())
    };
    assert_eq!(
        credit["Type"], "ACCRECCREDIT",
        "a customer credit, not a vendor one: {credit}"
    );
    assert_eq!(credit["CurrencyCode"], "USD");
    assert_eq!(credit["Date"], "2026-10-28");
    assert_eq!(
        credit["LineItems"][0]["Description"], "Decommissioned site, October",
        "the line reaches the provider: {credit}"
    );
    assert_eq!(
        application["Allocations"][0]["Invoice"]["InvoiceID"], XERO_INVOICE,
        "and it comes off the invoice the customer holds: {application}"
    );
    assert_eq!(application["Allocations"][0]["Amount"], "40.00");

    let columns = credit_note_columns(&pool, note.id)
        .await
        .expect("the row exists");
    assert_eq!(columns.0.as_deref(), Some("xero"));
    assert_eq!(columns.1.as_deref(), Some(XERO_CREDIT_NOTE));
    assert_eq!(
        columns.2.as_deref(),
        Some("CN-0005"),
        "the number the customer sees is the provider's"
    );
    assert_eq!(
        note.external_number.as_deref(),
        Some("CN-0005"),
        "and the response says so, like a delegated invoice does"
    );
    assert_eq!(
        amount_credited(&pool, invoice_id).await,
        Decimal::from(40),
        "the local balance is credited by the one writer (PMS-953)"
    );
}

/// QuickBooks keeps the credit as its own document and applies it with a
/// payment of nothing.
#[mokosh_test]
async fn crediting_a_quickbooks_invoice_posts_a_credit_memo_and_a_zero_payment(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "quickbooks").await;
    seed_quickbooks_blob(&secrets).await;
    let (invoice_id, product_id) = delegated_invoice(
        &billing,
        &pool,
        db,
        InvoiceProviderKind::Quickbooks,
        QBO_CUSTOMER,
    )
    .await;

    let note = billing
        .create_credit_note(
            tenant(),
            "UTC",
            &credit_request(invoice_id, product_id),
            &ctx(),
        )
        .await
        .expect("credit the invoice");

    let (credit, application) = {
        let calls = stub.lock().unwrap();
        assert_eq!(calls.credits.len(), 1);
        assert_eq!(calls.applications.len(), 1);
        (calls.credits[0].clone(), calls.applications[0].clone())
    };
    assert_eq!(credit["CustomerRef"]["value"], QBO_CUSTOMER);
    assert_eq!(credit["Line"][0]["Amount"], "40.00");
    assert_eq!(
        credit["Line"][0]["SalesItemLineDetail"]["ItemRef"]["value"], "item-9",
        "the mapped item, which QuickBooks refuses the line without: {credit}"
    );
    assert!(
        credit.get("DueDate").is_none(),
        "nothing falls due on money owed back: {credit}"
    );
    assert_eq!(
        application["TotalAmt"], "0.00",
        "no money arrived, so the payment totals nothing: {application}"
    );
    assert_eq!(application["Line"][0]["LinkedTxn"][0]["TxnId"], "1042");
    assert_eq!(application["Line"][0]["LinkedTxn"][0]["TxnType"], "Invoice");
    assert_eq!(
        application["Line"][1]["LinkedTxn"][0]["TxnId"], QBO_CREDIT_MEMO,
        "and the credit that settled it: {application}"
    );
    assert_eq!(
        application["Line"][1]["LinkedTxn"][0]["TxnType"],
        "CreditMemo"
    );

    let columns = credit_note_columns(&pool, note.id)
        .await
        .expect("the row exists");
    assert_eq!(columns.0.as_deref(), Some("quickbooks"));
    assert_eq!(columns.1.as_deref(), Some(QBO_CREDIT_MEMO));
    assert_eq!(columns.2.as_deref(), Some("1009"));
}

/// A provider that refuses the credit document leaves no local credit
/// note and no credited amount: the push is inside the transaction, so
/// the operator retries rather than reading a credit the customer's own
/// copy does not show.
#[mokosh_test]
async fn a_refused_credit_document_leaves_no_local_row(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "xero").await;
    seed_xero_blob(&secrets).await;
    let (invoice_id, _product) =
        delegated_invoice(&billing, &pool, db, InvoiceProviderKind::Xero, XERO_CONTACT).await;
    stub.lock().unwrap().credit_refuses_with = Some(StatusCode::BAD_REQUEST);

    let err = billing
        .create_credit_note(tenant(), "UTC", &credit_request(invoice_id, None), &ctx())
        .await
        .expect_err("the provider refused");

    assert_eq!(
        credit_note_count(&pool).await,
        0,
        "nothing local was written: {err:?}"
    );
    assert_eq!(
        amount_credited(&pool, invoice_id).await,
        Decimal::ZERO,
        "and the invoice still says the customer owes it all"
    );
    assert_eq!(
        stub.lock().unwrap().applications.len(),
        0,
        "and nothing was applied, because there was nothing to apply"
    );
}

/// A refused APPLICATION is not fatal, which is the asymmetry this path
/// is built around: the credit document exists over there, so rolling
/// back would strand a provider document nothing local points at.
#[mokosh_test]
async fn a_refused_application_keeps_the_credit_note_and_the_provider_id(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "xero").await;
    seed_xero_blob(&secrets).await;
    let (invoice_id, _product) =
        delegated_invoice(&billing, &pool, db, InvoiceProviderKind::Xero, XERO_CONTACT).await;
    stub.lock().unwrap().application_refuses_with = Some(StatusCode::BAD_REQUEST);

    let note = billing
        .create_credit_note(tenant(), "UTC", &credit_request(invoice_id, None), &ctx())
        .await
        .expect("the credit note stands even though the provider would not apply it");

    assert_eq!(
        stub.lock().unwrap().applications.len(),
        1,
        "the application WAS attempted"
    );
    let columns = credit_note_columns(&pool, note.id)
        .await
        .expect("the row exists");
    assert_eq!(
        columns.1.as_deref(),
        Some(XERO_CREDIT_NOTE),
        "and the provider's id is kept, because that document is findable"
    );
    assert_eq!(
        amount_credited(&pool, invoice_id).await,
        Decimal::from(40),
        "the local credit stands: the customer is owed it either way"
    );
    assert_eq!(
        note.notes, None,
        "and nothing about the provider leaks onto the customer's document"
    );
}

/// Voiding a delegated credit note takes the allocation off first and
/// then voids: Xero will not change a document an allocation stands
/// against, and taking it off is what puts the invoice back.
#[mokosh_test]
async fn voiding_a_delegated_credit_note_unallocates_then_voids_in_xero(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "xero").await;
    seed_xero_blob(&secrets).await;
    let (invoice_id, _product) =
        delegated_invoice(&billing, &pool, db, InvoiceProviderKind::Xero, XERO_CONTACT).await;
    let note = billing
        .create_credit_note(tenant(), "UTC", &credit_request(invoice_id, None), &ctx())
        .await
        .expect("credit the invoice");

    let voided = billing
        .void_credit_note(tenant(), note.id, &ctx())
        .await
        .expect("void the credit note");

    let (unallocations, voids) = {
        let calls = stub.lock().unwrap();
        (calls.unallocations.clone(), calls.credit_voids.clone())
    };
    assert_eq!(
        unallocations,
        vec![(XERO_CREDIT_NOTE.to_string(), XERO_ALLOCATION.to_string())],
        "the allocation comes off first"
    );
    assert_eq!(voids.len(), 1, "and the credit note is voided once");
    assert_eq!(voids[0].0, XERO_CREDIT_NOTE);
    assert_eq!(voids[0].1["Status"], "VOIDED");

    assert_eq!(voided.status, CreditNoteStatus::Void);
    assert_eq!(
        amount_credited(&pool, invoice_id).await,
        Decimal::ZERO,
        "and the local balance walks back, because only issued notes count (PMS-953)"
    );
}

/// A credit note Xero has already voided is `AlreadyVoided` rather than a
/// refusal, so the local void still goes through.
#[mokosh_test]
async fn a_credit_note_the_provider_already_voided_is_not_an_error(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "xero").await;
    seed_xero_blob(&secrets).await;
    let (invoice_id, _product) =
        delegated_invoice(&billing, &pool, db, InvoiceProviderKind::Xero, XERO_CONTACT).await;
    let note = billing
        .create_credit_note(tenant(), "UTC", &credit_request(invoice_id, None), &ctx())
        .await
        .expect("credit the invoice");
    {
        let mut calls = stub.lock().unwrap();
        calls.xero_credit_status = "VOIDED".to_string();
        calls.xero_credit_allocated = false;
    }

    let voided = billing
        .void_credit_note(tenant(), note.id, &ctx())
        .await
        .expect("the local void still stands");

    assert_eq!(voided.status, CreditNoteStatus::Void);
    assert_eq!(
        stub.lock().unwrap().credit_voids.len(),
        0,
        "and the provider is not told to void what it has already voided"
    );
}

/// QuickBooks is voided with the token from the read that preceded it,
/// and it unapplies the payment itself.
#[mokosh_test]
async fn voiding_tells_quickbooks_with_the_token_it_just_read(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "quickbooks").await;
    seed_quickbooks_blob(&secrets).await;
    let (invoice_id, product_id) = delegated_invoice(
        &billing,
        &pool,
        db,
        InvoiceProviderKind::Quickbooks,
        QBO_CUSTOMER,
    )
    .await;
    let note = billing
        .create_credit_note(
            tenant(),
            "UTC",
            &credit_request(invoice_id, product_id),
            &ctx(),
        )
        .await
        .expect("credit the invoice");

    billing
        .void_credit_note(tenant(), note.id, &ctx())
        .await
        .expect("void the credit note");

    let voids = stub.lock().unwrap().credit_voids.clone();
    assert_eq!(voids.len(), 1);
    assert_eq!(voids[0].1["Id"], QBO_CREDIT_MEMO);
    assert_eq!(
        voids[0].1["SyncToken"], "1",
        "the token from the read, which QuickBooks rejects a write without"
    );
    assert_eq!(
        stub.lock().unwrap().unallocations.len(),
        0,
        "and no unallocation call, because QuickBooks does that itself"
    );
}

/// A credit note against a locally-issued invoice reaches no provider,
/// which is every credit note on a tenant that has delegated nothing.
#[mokosh_test]
async fn a_credit_note_against_a_local_invoice_calls_nothing(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (billing, _db, _secrets) = service_with_dispatch(&pool, &base, true).await;

    // No connection, so `create_invoice` took the local path and wrote no
    // external pair.
    let invoice = billing
        .create_invoice(tenant(), &invoice_request(company_id, None), &ctx())
        .await
        .expect("create the invoice");
    billing
        .update_invoice(tenant(), invoice.id, &send_request(), &ctx())
        .await
        .expect("send the invoice, which is what freezes it");

    let note = billing
        .create_credit_note(tenant(), "UTC", &credit_request(invoice.id, None), &ctx())
        .await
        .expect("credit the invoice");

    {
        let calls = stub.lock().unwrap();
        assert_eq!(calls.credits.len(), 0, "no provider was asked");
        assert_eq!(calls.applications.len(), 0);
    }
    assert_eq!(
        credit_note_columns(&pool, note.id).await,
        Some((None, None, None)),
        "and the row carries no provider"
    );
    assert_eq!(
        amount_credited(&pool, invoice.id).await,
        Decimal::from(40),
        "while the local credit works exactly as it did"
    );
}

/// A QuickBooks credit line that names no product is refused by name,
/// before any call: a QuickBooks sales line carries the item it credits,
/// and guessing one would file the credit against the wrong revenue.
#[mokosh_test]
async fn a_quickbooks_credit_line_without_a_product_is_refused(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (_admin, _email, _password) = common::seed_admin(&pool).await;
    let (billing, db, secrets) = service_with_dispatch(&pool, &base, true).await;

    delegate(&pool, "quickbooks").await;
    seed_quickbooks_blob(&secrets).await;
    let (invoice_id, _product) = delegated_invoice(
        &billing,
        &pool,
        db,
        InvoiceProviderKind::Quickbooks,
        QBO_CUSTOMER,
    )
    .await;

    let err = billing
        .create_credit_note(tenant(), "UTC", &credit_request(invoice_id, None), &ctx())
        .await
        .expect_err("a line with no product cannot become a QuickBooks credit");

    let message = format!("{err:?}");
    assert!(
        message.contains("product_id"),
        "the refusal says what to set: {message}"
    );
    assert_eq!(
        credit_note_count(&pool).await,
        0,
        "and no local row was written"
    );
    assert_eq!(
        stub.lock().unwrap().credits.len(),
        0,
        "and the provider was never asked"
    );
}
