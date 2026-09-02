//! PMS-806: `list_contacts` hydrates `phones` and `companies` for a whole page
//! with ONE query per child table, not one per row.
//!
//! The obvious implementation of a child collection is a loop: fetch the page,
//! then fetch each contact's phones and links. That is N+1 and it degrades
//! silently as a tenant's contact list grows. The read path batches both child
//! reads with `contact_id = ANY($2)`, which is what this file pins.
//!
//! The count comes from a `tracing` subscriber that records `sqlx::query`
//! events (the `tests/contract_sweep_query_budget.rs` pattern). This file holds
//! exactly ONE test on purpose: the subscriber is process-global, so a second
//! test running concurrently would count its statements as well.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contacts::{ContactFilter, ContactService};
use mokosh_server::utils::pagination::PaginationParams;
use mokosh_server::Database;

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

/// Pulls the SQL text off an `sqlx::query` event. sqlx records the full text as
/// `db.statement` and a one-line version as `summary`; either identifies the
/// statement, so prefer the full text and fall back to the summary.
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

/// Contacts on the measured page: enough that a per-row read shows up clearly
/// against the fixed per-page cost.
const CONTACTS: usize = 5;

#[sqlx::test]
async fn a_contact_page_reads_each_child_table_once(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let tenant = common::DEFAULT_TENANT_ID;
    let company = common::seed_company(&pool).await;

    for i in 0..CONTACTS {
        let contact = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name) \
             VALUES ($1, $2, $3, $4, 'Budget')",
        )
        .bind(contact)
        .bind(tenant)
        .bind(company)
        .bind(format!("Contact{i}"))
        .execute(&pool)
        .await
        .expect("seed contact");
        // Two phones and one link each, so both hydration queries return rows.
        for (kind, number, primary, order) in [
            ("work", format!("+1555010{i}"), true, 0),
            ("mobile", format!("+1555020{i}"), false, 1),
        ] {
            sqlx::query(
                "INSERT INTO contact_phones \
                 (tenant_id, contact_id, phone_type, number, is_primary, sort_order) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(tenant)
            .bind(contact)
            .bind(kind)
            .bind(number)
            .bind(primary)
            .bind(order)
            .execute(&pool)
            .await
            .expect("seed contact phone");
        }
        sqlx::query(
            "INSERT INTO contact_companies (tenant_id, contact_id, company_id, is_primary) \
             VALUES ($1, $2, $3, TRUE)",
        )
        .bind(tenant)
        .bind(contact)
        .bind(company)
        .execute(&pool)
        .await
        .expect("seed contact link");
    }

    let svc = ContactService::new(Database::from_pool(pool.clone()));
    let filter = ContactFilter::default();
    let pagination = PaginationParams::default();

    recorder.armed.store(true, Ordering::SeqCst);
    let (contacts, total) = svc
        .list_contacts(TenantId::from_trusted(tenant), &filter, &pagination)
        .await
        .expect("list contacts");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(
        total as usize, CONTACTS,
        "the measured page covers them all"
    );
    assert!(
        contacts
            .iter()
            .all(|c| c.phones.len() == 2 && c.companies.len() == 1),
        "every contact on the page is hydrated"
    );

    let statements = recorder.take();
    for (table, label) in [
        ("contact_phones", "phones"),
        ("contact_companies", "company links"),
    ] {
        let reads: Vec<&String> = statements
            .iter()
            .filter(|s| s.starts_with("SELECT") && s.contains(table))
            .collect();
        assert_eq!(
            reads.len(),
            1,
            "hydrating {label} for {CONTACTS} contacts must read `{table}` exactly once \
             (N+1 regression), got: {reads:#?}"
        );
        assert!(
            reads[0].contains("ANY("),
            "the {label} read must be the batched `= ANY($n)` form: {reads:#?}"
        );
    }
}
