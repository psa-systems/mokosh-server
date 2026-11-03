//! PMS-1561 (F5): a delegated `create_invoice` call runs the pre-pass's
//! guards - company, payment term, and per-line product sellability - once,
//! not twice.
//!
//! `create_invoice` runs a pre-pass ahead of the external issuer call (so a
//! Xero/QuickBooks round trip never happens under the invoice-number
//! sequence lock) that asserts the same company/payment-term/sellability
//! facts the main write transaction asserts a few lines later. Nothing
//! between the two transactions can change the answer within one request, so
//! the second pass was pure duplicate cost. This pins that the duplicate is
//! gone by counting the underlying SQL statements: a connection-free
//! `IssuerDispatcher` with the feature flag on is enough to enter the
//! pre-pass branch (`delegation_enabled()` only reads the flag), and with no
//! provider connected the plan resolves to `Local`, so the invoice is still
//! written exactly as the non-delegated path would write it.
//!
//! The count comes from a `tracing` subscriber that records `sqlx::query`
//! events (the `tests/suites/contact_hydration_query_budget.rs` pattern).
//! This file holds exactly ONE test on purpose: the subscriber is
//! process-global, so a second test running concurrently would count its
//! statements as well.

use crate::common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::NaiveDate;
use mokosh_server::db::Database;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::billing::invoice_issuer_app::{IssuerApp, IssuerApps};
use mokosh_server::modules::billing::invoice_issuer_dispatch::IssuerDispatcher;
use mokosh_server::modules::billing::invoice_issuer_mappings::InvoiceIssuerMappingService;
use mokosh_server::modules::billing::models::{
    CreateInvoiceLineRequest, CreateInvoiceRequest, InvoiceLineType,
};
use mokosh_server::modules::billing::provider_invoice::{QuickBooksClient, XeroClient};
use mokosh_server::modules::billing::service::BillingService;
use mokosh_server::modules::features::{Feature, FeatureSnapshot, FeatureToggles};
use mokosh_server::modules::integrations::IntegrationsService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretProvider};
use mokosh_test::mokosh_test;
use rust_decimal::Decimal;
use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

/// Statements observed while [`Recorder::armed`] is set.
#[derive(Default)]
struct Recorder {
    armed: AtomicBool,
    statements: Mutex<Vec<String>>,
}

impl Recorder {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.statements.lock().expect("statement log"))
    }
}

#[derive(Default)]
struct SqlVisitor {
    statement: Option<String>,
    summary: Option<String>,
}

impl Visit for SqlVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "db.statement" => self.statement = Some(format!("{value:?}")),
            "summary" => self.summary = Some(format!("{value:?}")),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "db.statement" => self.statement = Some(value.to_string()),
            "summary" => self.summary = Some(value.to_string()),
            _ => {}
        }
    }
}

struct RecordingLayer(Arc<Recorder>);

impl<S: tracing::Subscriber> Layer<S> for RecordingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "sqlx::query" || !self.0.armed.load(Ordering::SeqCst) {
            return;
        }
        let mut visitor = SqlVisitor::default();
        event.record(&mut visitor);
        let sql = visitor
            .statement
            .or(visitor.summary)
            .unwrap_or_else(|| "<no sql field>".to_string());
        self.0
            .statements
            .lock()
            .expect("statement log")
            .push(sql.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

/// The deployment's applications, as a fixture supplies them. Never reached
/// here: with no provider connected, `IssuerDispatcher::plan` resolves to
/// `Local` before either client is asked to do anything.
fn fixture_apps() -> IssuerApps {
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

#[mokosh_test]
async fn a_delegated_create_invoice_asserts_its_guards_once(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let company_id = common::seed_company(&pool).await;
    let product_id: Uuid = sqlx::query_scalar(
        "INSERT INTO products (id, tenant_id, name, unit_price) \
         VALUES ($1, $2, 'Managed services', 150) RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("seed a product");
    let payment_term_id: Uuid = sqlx::query_scalar(
        "INSERT INTO payment_terms (tenant_id, name, is_default, is_active, net_days) \
         VALUES ($1, 'PMS-1561 budget term', FALSE, TRUE, 15) RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("seed a payment term");

    let app_pool = common::build_app_role_pool(&pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let toggles = FeatureToggles::from_rows([(Feature::DelegatedInvoiceIssuer.key(), true)]);
    let dispatcher = IssuerDispatcher::new(
        FeatureSnapshot::new(toggles),
        Arc::new(IntegrationsService::new(db.clone(), secrets.clone())),
        Arc::new(InvoiceIssuerMappingService::new(db.clone())),
        secrets.clone(),
        Arc::new(fixture_apps()),
        Arc::new(XeroClient::new()),
        Arc::new(QuickBooksClient::new()),
    );
    let billing = BillingService::new(db).with_invoice_dispatch(Arc::new(dispatcher));

    let request = CreateInvoiceRequest {
        company_id,
        billing_contact_id: None,
        contract_id: None,
        invoice_date: NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
        // None: resolve_due_date must read the named term's net_days, which
        // is a second statement the pre-pass and the main pass could each
        // duplicate.
        due_date: None,
        payment_terms: None,
        payment_term_id: Some(payment_term_id),
        tax_amount: None,
        tax_rate_id: None,
        discount_amount: None,
        currency: Some("USD".to_string()),
        notes: None,
        po_number: None,
        lines: vec![CreateInvoiceLineRequest {
            line_type: InvoiceLineType::Service,
            product_id: Some(product_id),
            is_taxable: false,
            description: "Managed services, October".to_string(),
            quantity: Decimal::from(2),
            unit_price: Decimal::from(150),
            ticket_id: None,
            project_id: None,
            sort_order: 0,
        }],
    };

    recorder.armed.store(true, Ordering::SeqCst);
    let created = billing
        .create_invoice(
            tenant,
            &request,
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create the invoice");
    recorder.armed.store(false, Ordering::SeqCst);

    assert!(
        !created.invoice_number.is_empty(),
        "no provider is connected, so the plan resolves to Local and the \
         invoice is still written"
    );

    let statements = recorder.take();
    // `load_invoice` (PMS-959's one response assembly) re-reads `company_name`
    // with this exact SQL text to build the response, which is a legitimate
    // read distinct from `assert_company_in_tenant`'s check and happens on
    // every `create_invoice` call regardless of this dedup, so the company
    // needle's budget is 2 (one validation, one response assembly) rather
    // than the other three guards' 1 (validation only, no response field
    // shares their exact text).
    for (needle, label, expected) in [
        (
            "SELECT name FROM companies WHERE tenant_id",
            "assert_company_in_tenant plus load_invoice's company_name read",
            2,
        ),
        (
            "SELECT 1 FROM payment_terms WHERE tenant_id",
            "assert_payment_term_in_tenant",
            1,
        ),
        (
            "SELECT id, net_days FROM payment_terms",
            "resolve_due_date's term lookup",
            1,
        ),
        (
            "SELECT is_active FROM products WHERE id",
            "assert_product_sellable",
            1,
        ),
    ] {
        let reads: Vec<&String> = statements.iter().filter(|s| s.contains(needle)).collect();
        assert_eq!(
            reads.len(),
            expected,
            "{label} must run exactly {expected} time(s) across the pre-pass and \
             the main transaction, not once each, got: {reads:#?}"
        );
    }
}
