//! PMS-1541: reimbursing a claim into the provider's ledger, end to end.
//!
//! The bill harness (`bill_delegation`) in the other direction: both
//! clients point at an axum stub on `127.0.0.1:0`, every dependency of
//! `IssuerDispatcher::new` is injected, and the credential blob is written
//! with the production serialiser so the fixture cannot drift from the
//! shape the code parses.
//!
//! What only an integration test shows here: that the push happens on
//! REIMBURSE and not on create, so a rejected claim never reaches the
//! ledger; that it happens before the write transaction, so a provider
//! that refuses leaves the claim `approved` for somebody to retry; and
//! that each of the three missing mappings is refused by name.

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
    CreateExpenseRequest, ExpenseLineInput, ExpensesService, UpsertExpenseCategoryRequest,
};
use mokosh_server::modules::features::{Feature, FeatureSnapshot, FeatureToggles};
use mokosh_server::modules::integrations::IntegrationsService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretKey, SecretProvider};
use mokosh_server::utils::error::AppError;
use mokosh_test::mokosh_test;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const XERO_CONTACT: &str = "3f6c6a2e-9d41-4a39-9f6a-6d1a1c2b3d4e";
const XERO_BANK_ACCOUNT: &str = "13918178-849a-247f-8ed7-c7b1f5e7e71c";
const QBO_BANK_ACCOUNT: &str = "35";
const QBO_ACCOUNT: &str = "7";
const QBO_CONTACT: &str = "56";

#[derive(Default)]
struct Calls {
    spends: Vec<Value>,
    refuse_with: Option<StatusCode>,
}

type Stub = Arc<Mutex<Calls>>;

async fn xero_spend(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.spends.push(body);
    if let Some(status) = calls.refuse_with {
        return (status, Json(json!({ "Message": "the provider refused" })));
    }
    (
        StatusCode::OK,
        Json(json!({
            "BankTransactions": [{
                "BankTransactionID": "7c1f4e2a-9b3d-4f5e-8a6b-2d4f6a8c0e22",
                "Type": "SPEND",
                "Status": "AUTHORISED",
            }]
        })),
    )
}

async fn quickbooks_spend(State(stub): State<Stub>, Json(body): Json<Value>) -> impl IntoResponse {
    let mut calls = stub.lock().unwrap();
    calls.spends.push(body);
    if let Some(status) = calls.refuse_with {
        return (
            status,
            Json(json!({ "Fault": { "type": "ValidationFault" } })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "Purchase": { "Id": "4471", "SyncToken": "0" } })),
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

async fn start_stub() -> (Stub, String) {
    let stub: Stub = Arc::new(Mutex::new(Calls::default()));
    let app = axum::Router::new()
        .route(
            "/api.xro/2.0/BankTransactions",
            axum::routing::post(xero_spend),
        )
        .route(
            "/v3/company/{realm}/purchase",
            axum::routing::post(quickbooks_spend),
        )
        .route("/connect/token", axum::routing::post(token))
        .route("/oauth2/v1/tokens/bearer", axum::routing::post(token))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (stub, base)
}

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

/// Connect a provider with Bills and expenses delegated, and optionally
/// with the account a reimbursement is paid from.
async fn connect(pool: &PgPool, provider: &str, payment_account: Option<&str>) {
    sqlx::query(
        "INSERT INTO integrations \
           (tenant_id, provider, status, enabled_capabilities, external_payment_account_id) \
         VALUES ($1, $2, 'connected', ARRAY['bills_and_expenses']::text[], $3) \
         ON CONFLICT (tenant_id, provider) DO UPDATE \
           SET status = 'connected', \
               enabled_capabilities = EXCLUDED.enabled_capabilities, \
               external_payment_account_id = EXCLUDED.external_payment_account_id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(provider)
    .bind(payment_account)
    .execute(pool)
    .await
    .expect("connect the provider");
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

fn ctx() -> AuditCtx {
    AuditCtx::system(common::DEFAULT_TENANT_ID)
}

fn tenant() -> TenantId {
    TenantId::from_trusted(common::DEFAULT_TENANT_ID)
}

async fn category(svc: &ExpensesService) -> Uuid {
    svc.create_expense_category(
        tenant(),
        &UpsertExpenseCategoryRequest {
            name: "Travel".to_string(),
            is_active: true,
        },
        &ctx(),
    )
    .await
    .expect("category")
    .id
}

/// A claim for 32.50, approved and ready to be paid back.
async fn approved_claim(svc: &ExpensesService, user_id: Uuid, category_id: Option<Uuid>) -> Uuid {
    let claim = svc
        .create_expense(
            tenant(),
            user_id,
            &CreateExpenseRequest {
                incurred_on: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
                currency: "USD".to_string(),
                notes: None,
                lines: vec![ExpenseLineInput {
                    category_id,
                    description: "Taxi to site".to_string(),
                    amount_minor: 32_50,
                    tax_minor: 0,
                    position: 0,
                }],
            },
            &ctx(),
        )
        .await
        .expect("claim");
    svc.submit_expense(tenant(), claim.expense.id, &ctx())
        .await
        .expect("submit");
    svc.approve_expense(tenant(), claim.expense.id, user_id, &ctx())
        .await
        .expect("approve");
    claim.expense.id
}

async fn external_columns(pool: &PgPool, id: Uuid) -> (Option<String>, Option<String>) {
    sqlx::query_as("SELECT external_provider, external_expense_id FROM expenses WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read the claim row")
}

/// A delegated tenant has the reimbursement recorded in Xero as a SPEND,
/// and the local row records who holds it.
#[mokosh_test]
async fn a_reimbursement_is_recorded_in_xero_as_a_spend(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;

    connect(&pool, "xero", Some(XERO_BANK_ACCOUNT)).await;
    seed_xero_blob(&secrets).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_expense_account_mapping(tenant(), InvoiceProviderKind::Xero, category_id, "429")
        .await
        .expect("map the category");
    mappings
        .upsert_user_mapping(tenant(), InvoiceProviderKind::Xero, admin, XERO_CONTACT)
        .await
        .expect("map the person");

    let reimbursed = svc
        .reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect("reimburse");

    let (sent, count) = {
        let calls = stub.lock().unwrap();
        (calls.spends.first().cloned(), calls.spends.len())
    };
    let sent = sent.expect("Xero was asked");
    assert_eq!(count, 1, "Xero is asked exactly once");
    assert_eq!(sent["Type"], "SPEND", "money leaving, not arriving: {sent}");
    assert_eq!(sent["BankAccount"]["AccountID"], XERO_BANK_ACCOUNT);
    assert_eq!(sent["Contact"]["ContactID"], XERO_CONTACT);
    assert_eq!(sent["LineItems"][0]["LineAmount"], "32.50");
    assert_eq!(sent["LineItems"][0]["AccountCode"], "429");

    assert_eq!(reimbursed.status, "reimbursed");
    let columns = external_columns(&pool, claim).await;
    assert_eq!(columns.0.as_deref(), Some("xero"));
    assert_eq!(
        columns.1.as_deref(),
        Some("7c1f4e2a-9b3d-4f5e-8a6b-2d4f6a8c0e22"),
        "the provider's own id is what a reconciliation reads back"
    );
}

/// QuickBooks gets a purchase, with the person in `EntityRef`.
#[mokosh_test]
async fn a_reimbursement_is_recorded_in_quickbooks_as_a_purchase(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;

    connect(&pool, "quickbooks", Some(QBO_BANK_ACCOUNT)).await;
    seed_quickbooks_blob(&secrets).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_expense_account_mapping(
            tenant(),
            InvoiceProviderKind::Quickbooks,
            category_id,
            QBO_ACCOUNT,
        )
        .await
        .expect("map the category");
    mappings
        .upsert_user_mapping(
            tenant(),
            InvoiceProviderKind::Quickbooks,
            admin,
            QBO_CONTACT,
        )
        .await
        .expect("map the person");

    svc.reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect("reimburse");

    let sent = {
        let calls = stub.lock().unwrap();
        assert_eq!(calls.spends.len(), 1);
        calls.spends[0].clone()
    };
    assert_eq!(sent["AccountRef"]["value"], QBO_BANK_ACCOUNT);
    assert_eq!(sent["PaymentType"], "Bank");
    assert_eq!(
        sent["Line"][0]["AccountBasedExpenseLineDetail"]["AccountRef"]["value"],
        QBO_ACCOUNT
    );
    assert_eq!(sent["EntityRef"]["value"], QBO_CONTACT);

    let columns = external_columns(&pool, claim).await;
    assert_eq!(columns.0.as_deref(), Some("quickbooks"));
    assert_eq!(columns.1.as_deref(), Some("4471"));
}

/// QuickBooks takes the claim without a mapped person: the counterparty is
/// optional there, where Xero refuses the call without one.
#[mokosh_test]
async fn quickbooks_takes_a_claim_from_an_unmapped_person(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;

    connect(&pool, "quickbooks", Some(QBO_BANK_ACCOUNT)).await;
    seed_quickbooks_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_expense_account_mapping(
            tenant(),
            InvoiceProviderKind::Quickbooks,
            category_id,
            QBO_ACCOUNT,
        )
        .await
        .expect("map the category");

    svc.reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect("reimburse");

    let sent = {
        let calls = stub.lock().unwrap();
        calls.spends[0].clone()
    };
    assert!(
        sent.get("EntityRef").is_none(),
        "no counterparty rather than a null QuickBooks would reject: {sent}"
    );
}

/// The switch off is the untouched local path: no provider call, both
/// columns NULL, and the claim still reimbursed.
#[mokosh_test]
async fn the_switch_off_leaves_the_local_path_alone(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, false).await;
    let category_id = category(&svc).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;

    // Everything a delegated tenant has. Only the deployment switch is off.
    connect(&pool, "xero", Some(XERO_BANK_ACCOUNT)).await;
    seed_xero_blob(&secrets).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_expense_account_mapping(tenant(), InvoiceProviderKind::Xero, category_id, "429")
        .await
        .expect("map the category");
    mappings
        .upsert_user_mapping(tenant(), InvoiceProviderKind::Xero, admin, XERO_CONTACT)
        .await
        .expect("map the person");

    let reimbursed = svc
        .reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect("reimburse");

    assert_eq!(
        stub.lock().unwrap().spends.len(),
        0,
        "the flag is off: no provider is reached at all"
    );
    assert_eq!(reimbursed.status, "reimbursed");
    assert_eq!(external_columns(&pool, claim).await, (None, None));
}

/// The push is on reimburse, so submitting and approving reach no
/// provider: a rejected claim must never appear in the ledger.
#[mokosh_test]
async fn nothing_is_sent_before_the_claim_is_paid_back(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;

    connect(&pool, "xero", Some(XERO_BANK_ACCOUNT)).await;
    seed_xero_blob(&secrets).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_expense_account_mapping(tenant(), InvoiceProviderKind::Xero, category_id, "429")
        .await
        .expect("map the category");
    mappings
        .upsert_user_mapping(tenant(), InvoiceProviderKind::Xero, admin, XERO_CONTACT)
        .await
        .expect("map the person");

    // Approved is as far as the lifecycle goes without a reimbursement.
    let approved = approved_claim(&svc, admin, Some(category_id)).await;
    assert_eq!(
        stub.lock().unwrap().spends.len(),
        0,
        "an approved claim is still internal"
    );

    // And a rejected one must never appear in the ledger at all.
    let rejected = svc
        .create_expense(
            tenant(),
            admin,
            &CreateExpenseRequest {
                incurred_on: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
                currency: "USD".to_string(),
                notes: None,
                lines: vec![ExpenseLineInput {
                    category_id: Some(category_id),
                    description: "Hotel".to_string(),
                    amount_minor: 10_000,
                    tax_minor: 0,
                    position: 0,
                }],
            },
            &ctx(),
        )
        .await
        .expect("claim")
        .expense
        .id;
    svc.submit_expense(tenant(), rejected, &ctx())
        .await
        .expect("submit");
    svc.reject_expense(tenant(), rejected, &ctx())
        .await
        .expect("reject");

    assert_eq!(
        stub.lock().unwrap().spends.len(),
        0,
        "and a rejected claim never reaches the ledger"
    );
    for id in [approved, rejected] {
        assert_eq!(external_columns(&pool, id).await, (None, None), "{id}");
    }
}

/// A provider that refuses leaves the claim approved, which is the state
/// somebody can retry from.
#[mokosh_test]
async fn a_refusing_provider_leaves_the_claim_approved(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;

    connect(&pool, "xero", Some(XERO_BANK_ACCOUNT)).await;
    seed_xero_blob(&secrets).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_expense_account_mapping(tenant(), InvoiceProviderKind::Xero, category_id, "429")
        .await
        .expect("map the category");
    mappings
        .upsert_user_mapping(tenant(), InvoiceProviderKind::Xero, admin, XERO_CONTACT)
        .await
        .expect("map the person");
    stub.lock().unwrap().refuse_with = Some(StatusCode::BAD_REQUEST);

    let err = svc
        .reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect_err("the provider refused");

    assert!(
        !stub.lock().unwrap().spends.is_empty(),
        "the provider WAS asked: {err:?}"
    );
    let row = svc.get_expense(tenant(), claim).await.expect("read");
    assert_eq!(
        row.expense.status, "approved",
        "the claim stays where somebody can retry it"
    );
    assert_eq!(external_columns(&pool, claim).await, (None, None));
}

/// Each missing mapping is refused by name, and the claim stays approved.
#[mokosh_test]
async fn every_missing_mapping_is_refused_by_name(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    seed_xero_blob(&secrets).await;

    // 1. No account to reimburse from.
    connect(&pool, "xero", None).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;
    let err = svc
        .reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect_err("no payment account");
    let AppError::Conflict(message) = &err else {
        panic!("a client-stated conflict is not a server fault: {err:?}");
    };
    assert!(
        message.contains("payment-account"),
        "the refusal names the route that fixes it: {message}"
    );

    // 2. The account is set, but the category is not mapped.
    connect(&pool, "xero", Some(XERO_BANK_ACCOUNT)).await;
    let err = svc
        .reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect_err("unmapped category");
    let AppError::Conflict(message) = &err else {
        panic!("expected a conflict: {err:?}");
    };
    assert!(message.contains("expense-accounts/xero"), "{message}");

    // 3. The category is mapped, but the person is not, and Xero refuses a
    //    spend with no contact.
    mappings
        .upsert_expense_account_mapping(tenant(), InvoiceProviderKind::Xero, category_id, "429")
        .await
        .expect("map the category");
    let err = svc
        .reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect_err("unmapped person");
    let AppError::Conflict(message) = &err else {
        panic!("expected a conflict: {err:?}");
    };
    assert!(message.contains("people/xero"), "{message}");

    assert_eq!(
        stub.lock().unwrap().spends.len(),
        0,
        "nothing was sent for any of the three"
    );
    let row = svc.get_expense(tenant(), claim).await.expect("read");
    assert_eq!(row.expense.status, "approved");
}

/// A claim line with no category is refused: a reimbursement has to say
/// which account the cost posts to.
#[mokosh_test]
async fn a_categoryless_line_is_refused(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let claim = approved_claim(&svc, admin, None).await;

    connect(&pool, "xero", Some(XERO_BANK_ACCOUNT)).await;
    seed_xero_blob(&secrets).await;
    InvoiceIssuerMappingService::new(db)
        .upsert_user_mapping(tenant(), InvoiceProviderKind::Xero, admin, XERO_CONTACT)
        .await
        .expect("map the person");

    let err = svc
        .reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect_err("no category on the line");
    let AppError::Conflict(message) = &err else {
        panic!("expected a conflict: {err:?}");
    };
    assert!(
        message.contains("Taxi to site"),
        "the refusal names the line: {message}"
    );
    assert_eq!(stub.lock().unwrap().spends.len(), 0);
}

/// Connected without the capability is the local path: a tenant using Xero
/// for invoicing only does not get its reimbursements pushed.
#[mokosh_test]
async fn a_provider_without_the_capability_is_not_asked(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, _db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;

    sqlx::query(
        "INSERT INTO integrations \
           (tenant_id, provider, status, enabled_capabilities, external_payment_account_id) \
         VALUES ($1, 'xero', 'connected', ARRAY['invoicing']::text[], $2)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(XERO_BANK_ACCOUNT)
    .execute(&pool)
    .await
    .expect("connect for invoicing only");
    seed_xero_blob(&secrets).await;

    svc.reimburse_expense(tenant(), claim, &ctx())
        .await
        .expect("reimburse locally");

    assert_eq!(
        stub.lock().unwrap().spends.len(),
        0,
        "Invoicing is not Bills and expenses"
    );
    assert_eq!(external_columns(&pool, claim).await, (None, None));
}

/// PMS-1547 regression: a second `reimburse_expense` attempt that reaches
/// its own pre-check while a winning attempt's `transition_expense` holds
/// the row lock must block on that lock rather than racing it with a
/// plain unlocked read, and once unblocked must see the completed
/// transition and refuse before ever calling the provider. Before the
/// fix the pre-check was a plain `SELECT` that does not wait on another
/// transaction's row lock, so it would still read the pre-transition
/// `approved` status and dispatch to the provider a second time.
#[mokosh_test]
async fn a_losing_attempt_blocks_on_the_lock_and_never_dispatches(pool: PgPool) {
    let (stub, base) = start_stub().await;
    let (admin, _email, _pw) = common::seed_admin(&pool).await;
    let (svc, db, secrets) = service_with_dispatch(&pool, &base, true).await;
    let category_id = category(&svc).await;
    let claim = approved_claim(&svc, admin, Some(category_id)).await;

    connect(&pool, "xero", Some(XERO_BANK_ACCOUNT)).await;
    seed_xero_blob(&secrets).await;
    let mappings = InvoiceIssuerMappingService::new(db);
    mappings
        .upsert_expense_account_mapping(tenant(), InvoiceProviderKind::Xero, category_id, "429")
        .await
        .expect("map the category");
    mappings
        .upsert_user_mapping(tenant(), InvoiceProviderKind::Xero, admin, XERO_CONTACT)
        .await
        .expect("map the person");

    // Hold the row lock open on a separate connection, as if a winning
    // attempt's own `transition_expense` already took it and is about to
    // commit its transition to `reimbursed`.
    let mut holder = pool.begin().await.expect("open the holding transaction");
    sqlx::query("SELECT id FROM expenses WHERE id = $1 FOR UPDATE")
        .bind(claim)
        .execute(&mut *holder)
        .await
        .expect("take the row lock");

    let losing_svc = svc.clone();
    let (losing_result, ()) = tokio::join!(
        async move { losing_svc.reimburse_expense(tenant(), claim, &ctx()).await },
        async {
            // Long enough for the losing attempt to reach its own
            // `SELECT ... FOR UPDATE` pre-check and park behind this lock.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            sqlx::query(
                "UPDATE expenses SET status = 'reimbursed', reimbursed_at = NOW() WHERE id = $1",
            )
            .bind(claim)
            .execute(&mut *holder)
            .await
            .expect("simulate the winning attempt's own commit");
            holder.commit().await.expect("release the row lock");
        },
    );

    assert!(
        matches!(losing_result, Err(AppError::Conflict(_))),
        "the blocked attempt must see the post-transition status and refuse: {losing_result:?}"
    );
    assert_eq!(
        stub.lock().unwrap().spends.len(),
        0,
        "the attempt that lost the race must never reach the provider"
    );
}
