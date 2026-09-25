//! PMS-1246: `TicketService::create_ticket` validates every foreign id the
//! request body names against its own tenant (PMS-333's "an FK check bypasses
//! RLS" rule) before it links them. Before this it did so with
//! `validate_fk`/`validate_fk_opt`, one `begin_with_tenant` transaction per
//! id, so a create naming five foreign tables cost five round trips before the
//! insert even started. `validate_fks` batches every check into ONE query
//! inside ONE transaction; this test pins that budget.
//!
//! The count comes from a `tracing` subscriber recording `sqlx::query`
//! events, the same technique `tests/bunyip_query_budget.rs` uses and for the
//! same reason this file holds exactly ONE test: the subscriber is
//! process-global.

use mokosh_test::mokosh_test;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::tickets::TicketService;
use mokosh_server::Database;

mod common;

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
async fn create_ticket_validates_every_fk_in_one_query(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let type_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ticket_types (tenant_id, name) VALUES ($1, 'Incident') RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("seed ticket type");
    let category_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ticket_categories (tenant_id, name) VALUES ($1, 'Hardware') RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("seed ticket category");
    let contact_id: Uuid = sqlx::query_scalar(
        "INSERT INTO contacts (tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, 'Jane', 'Doe', $3) RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(format!("jane.{}@example.com", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed contact");
    let site_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sites (tenant_id, company_id, name) VALUES ($1, $2, 'HQ') RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .fetch_one(&pool)
    .await
    .expect("seed site");

    let db = Database::from_pool(pool.clone());
    let service = TicketService::new(db);
    let tenant_id = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let request = mokosh_types::tickets::CreateTicketRequest {
        parent_ticket_id: None,
        title: "FK budget probe".to_string(),
        description: None,
        priority_id: None,
        type_id: Some(type_id),
        category_id: Some(category_id),
        queue_id: None,
        source: Default::default(),
        company_id,
        contact_id: Some(contact_id),
        site_id: Some(site_id),
        assigned_to_id: Some(admin_id),
        team_id: None,
        contract_id: None,
        sla_id: None,
        scheduled_start: None,
        scheduled_end: None,
        estimated_hours: None,
        is_billable: true,
        asset_id: None,
        custom_fields: serde_json::json!({}),
        tags: vec![],
        source_kb_article_id: None,
        procedure_kb_article_id: None,
        email_message_id: None,
        email_thread_id: None,
    };

    recorder.armed.store(true, Ordering::SeqCst);
    let ticket = service
        .create_ticket(
            tenant_id,
            admin_id,
            &request,
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("create ticket with six named FKs");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(ticket.company_id, company_id);

    let statements = recorder.take();
    let fk_checks: Vec<&String> = statements
        .iter()
        .filter(|s| s.contains("EXISTS(SELECT 1 FROM"))
        .collect();
    assert_eq!(
        fk_checks.len(),
        1,
        "six named FKs (company, type, category, contact, site, assigned_to) \
         must be validated in exactly one query, got: {statements:#?}"
    );
    let combined = &fk_checks[0];
    for table in [
        "companies",
        "ticket_types",
        "ticket_categories",
        "contacts",
        "sites",
        "users",
    ] {
        assert!(
            combined.contains(table),
            "the one FK query must check `{table}`: {combined}"
        );
    }
}
