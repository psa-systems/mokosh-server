//! PMS-1246: `AutomationEngine::process_rules` used to open one
//! `begin_with_tenant` transaction for the rule fetch, then `evaluate_conditions`
//! opened another per rule, then `execute_actions` opened one per action: a
//! ticket update firing 5 rules with 3 actions each cost 1 + 5 + 15 = 21
//! transactions before a single row was touched. `process_rules` now opens ONE
//! transaction for the whole run (rule fetch, the shared ticket read, and every
//! action); this test pins that budget.
//!
//! Every `begin_with_tenant` call issues exactly one
//! `SELECT set_config('app.current_tenant', ...)` before anything else on that
//! connection, so counting those statements counts transactions opened. Uses
//! the same recording-subscriber technique as `tests/fk_validation_query_budget.rs`
//! and `tests/bunyip_query_budget.rs`, and for the same reason holds exactly ONE
//! test: the subscriber is process-global.

use mokosh_test::mokosh_test;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::tickets::{AutomationEngine, TicketService};
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
            .filter(|s| !s.is_empty())
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
async fn process_rules_opens_one_transaction_for_the_whole_run(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let (admin_id, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let db = Database::from_pool(pool.clone());
    let tenant_id = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let request = mokosh_types::tickets::CreateTicketRequest {
        parent_ticket_id: None,
        title: "Automation budget probe".to_string(),
        description: None,
        priority_id: None,
        type_id: None,
        category_id: None,
        queue_id: None,
        source: Default::default(),
        company_id,
        contact_id: None,
        site_id: None,
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

    let ticket = TicketService::new(db.clone())
        .create_ticket(
            tenant_id,
            admin_id,
            &request,
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("seed ticket");

    // Five active rules for the same trigger, each with three no-condition
    // (always match) actions, so a single run fires all 15 actions. Each
    // action updates `tickets` in place with the ticket's own current ids,
    // rather than `add_note`: that action stamps a hardcoded nil
    // `created_by_id` (automation.rs's "System-generated" placeholder) and
    // `ticket_notes.created_by_id` is a NOT NULL FK to `users`, so it fails
    // 23503 against any real schema. That is a pre-existing defect outside
    // this issue's scope; this test does not exercise it.
    let actions = serde_json::json!([
        {"action_type": "assign_to", "params": {"user_id": admin_id.to_string()}},
        {"action_type": "set_priority", "params": {"priority_id": ticket.priority_id.to_string()}},
        {"action_type": "set_status", "params": {"status_id": ticket.status_id.to_string()}},
    ]);
    for i in 0..5 {
        sqlx::query(
            "INSERT INTO ticket_automation_rules \
             (tenant_id, name, is_active, trigger_type, conditions, actions, priority) \
             VALUES ($1, $2, TRUE, 'on_update', '[]'::jsonb, $3, $4)",
        )
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("Rule {i}"))
        .bind(&actions)
        .bind(i)
        .execute(&pool)
        .await
        .expect("seed automation rule");
    }

    let engine = AutomationEngine::new(db);

    recorder.armed.store(true, Ordering::SeqCst);
    engine
        .process_rules(
            tenant_id,
            ticket.id,
            mokosh_types::tickets::AutomationTrigger::OnUpdate,
        )
        .await
        .expect("process automation rules for the ticket update");
    recorder.armed.store(false, Ordering::SeqCst);

    let statements = recorder.take();
    let transactions_opened = statements
        .iter()
        .filter(|s| s.contains("set_config('app.current_tenant'"))
        .count();
    assert_eq!(
        transactions_opened, 1,
        "5 rules x 3 actions must run inside one transaction, not 1 + 5 + 15 = 21, got: {statements:#?}"
    );

    let stat_updates: i32 = sqlx::query_scalar(
        "SELECT run_count FROM ticket_automation_rules WHERE tenant_id = $1 AND name = 'Rule 0'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("read one rule's run_count");
    assert_eq!(
        stat_updates, 1,
        "every matched rule's run_count must be bumped once by the run"
    );
}
