//! PMS-1561 (F4): `IntegrationsService::get()` only pays for
//! `contact_sync_states` when the caller actually asked about
//! `Capability::Contacts`.
//!
//! `contact_sync_states` loops over all three contact-sync providers and
//! opens a transaction per provider through `contacts_enabled`. Before this,
//! `get()` ran it unconditionally, so `invoice_issuer_dispatch.rs`'s five
//! call sites (which only read `status`/`enabled_capabilities`, never any
//! contact-sync field) paid for up to three unnecessary transactions on
//! every per-bill, per-expense dispatch decision. This pins that a caller
//! asking about `Invoicing`/`BillsAndExpenses` never triggers the
//! `contact_sync_connections` read, while a caller asking about `Contacts`
//! still gets it (the page-level behaviour is unchanged).
//!
//! The count comes from a `tracing` subscriber that records `sqlx::query`
//! events (the `tests/suites/contact_hydration_query_budget.rs` pattern).
//! This file holds exactly ONE test on purpose: the subscriber is
//! process-global, so a second test running concurrently would count its
//! statements as well.

use crate::common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::integrations::{Capability, IntegrationProvider, IntegrationsService};
use mokosh_server::secrets::DatabaseSecretProvider;
use mokosh_test::mokosh_test;
use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

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

#[mokosh_test]
async fn only_a_contacts_caller_reads_contact_sync_connections(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    sqlx::query(
        "INSERT INTO integrations (tenant_id, provider, status, enabled_capabilities) \
         VALUES ($1, 'xero', 'connected', ARRAY['bills_and_expenses']::text[])",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed a bills_and_expenses integration");
    sqlx::query(
        "INSERT INTO contact_sync_connections (tenant_id, provider, account_email, is_active, sync_status) \
         VALUES ($1, 'google', 'budget-test@example.com', TRUE, 'success')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("seed a contact-sync connection");

    let app_pool = common::build_app_role_pool(&pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let secrets = Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let service = IntegrationsService::new(db, secrets);

    recorder.armed.store(true, Ordering::SeqCst);
    service
        .get(
            tenant,
            IntegrationProvider::Xero,
            Capability::BillsAndExpenses,
        )
        .await
        .expect("read xero");
    let after_bills_and_expenses = recorder.take();

    service
        .get(tenant, IntegrationProvider::Google, Capability::Contacts)
        .await
        .expect("read google");
    let after_contacts = recorder.take();
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(
        after_bills_and_expenses
            .iter()
            .filter(|s| s.contains("contact_sync_connections"))
            .count(),
        0,
        "Capability::BillsAndExpenses must never trigger contact_sync_states, got: \
         {after_bills_and_expenses:#?}"
    );
    assert_eq!(
        after_contacts
            .iter()
            .filter(|s| s.contains("contact_sync_connections"))
            .count(),
        1,
        "Capability::Contacts still gets the contact-sync read the page needs, got: \
         {after_contacts:#?}"
    );
}
