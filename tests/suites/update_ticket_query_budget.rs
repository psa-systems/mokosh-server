//! PMS-1682: `TicketService::update_ticket` used to run one `UPDATE tickets`
//! per optional field present on `UpdateTicketRequest` (up to 22 of them: ten
//! original plus the twelve PMS-1565 added), each its own round trip inside
//! the same transaction. A PATCH naming many fields paid many sequential
//! round trips for a single logical write. `update_ticket` now builds one
//! dynamic `UPDATE` via `sqlx::QueryBuilder` covering every present field.
//! This pins that budget.
//!
//! The count comes from a `tracing` subscriber recording `sqlx::query`
//! events, the same technique `tests/suites/fk_validation_query_budget.rs`
//! uses and for the same reason this file holds exactly ONE test: the
//! subscriber is process-global.

use mokosh_test::mokosh_test;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::tickets::TicketService;
use mokosh_server::Database;
use mokosh_types::tickets::{BillingStatus, UpdateTicketRequest};

use crate::common;

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
async fn update_ticket_coalesces_fourteen_fields_into_one_update(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact_id = common::seed_billing_contact(&pool, company_id).await;
    let team_id = common::seed_team(&pool, common::DEFAULT_TENANT_ID, "Budget team", None).await;

    let type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_types WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("seeded ticket type");
    let category_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_categories WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("seeded ticket category");
    let sla_id: Uuid =
        sqlx::query_scalar("SELECT id FROM sla_policies WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("seeded sla policy");

    let site_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sites (id, tenant_id, company_id, name) VALUES ($1, $2, $3, 'Budget site')",
    )
    .bind(site_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed site");

    let contract_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contracts (id, tenant_id, name, company_id, contract_type, start_date) \
         VALUES ($1, $2, 'Managed services', $3, 'managed_services', CURRENT_DATE)",
    )
    .bind(contract_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contract");

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let create_resp = app
        .client
        .post(app.url("/api/v1/tickets"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Query budget probe",
            "company_id": company_id,
            "custom_fields": {},
        }))
        .send()
        .await
        .expect("send create ticket");
    assert!(create_resp.status().is_success());
    let created: serde_json::Value = create_resp.json().await.expect("create ticket JSON");
    let ticket_id: Uuid = created["id"]
        .as_str()
        .expect("created ticket has id")
        .parse()
        .expect("ticket id is a uuid");

    let db = Database::from_pool(pool.clone());
    let service = TicketService::new(db);
    let tenant_id = TenantId::from_trusted(common::DEFAULT_TENANT_ID);

    let scheduled_start: DateTime<Utc> = "2026-01-05T09:00:00Z".parse().unwrap();
    let scheduled_end: DateTime<Utc> = "2026-01-05T17:00:00Z".parse().unwrap();

    // Fourteen optional fields at once, none of them status_id/priority_id
    // (those two keep their own closed_at/resolved_at side effect and are
    // covered by `tickets::update_ticket_persists_every_accepted_field`),
    // well past the "at least 10" the acceptance criteria asks for.
    let request = UpdateTicketRequest {
        title: None,
        description: None,
        status_id: None,
        priority_id: None,
        type_id: Some(Some(type_id)),
        category_id: Some(Some(category_id)),
        queue_id: None,
        contact_id: Some(Some(contact_id)),
        site_id: Some(Some(site_id)),
        assigned_to_id: None,
        team_id: Some(Some(team_id)),
        contract_id: Some(Some(contract_id)),
        sla_id: Some(Some(sla_id)),
        scheduled_start: Some(Some(scheduled_start)),
        scheduled_end: Some(Some(scheduled_end)),
        estimated_hours: Some(Some(4.5)),
        is_billable: Some(false),
        billing_status: Some(BillingStatus::ReadyToBill),
        asset_id: None,
        custom_fields: Some(serde_json::json!({"severity": "high"})),
        tags: Some(vec!["urgent".to_string(), "vip".to_string()]),
    };

    recorder.armed.store(true, Ordering::SeqCst);
    service
        .update_ticket(
            tenant_id,
            ticket_id,
            _admin_id,
            &request,
            &AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("update ticket with fourteen named fields");
    recorder.armed.store(false, Ordering::SeqCst);

    let statements = recorder.take();
    let column_writes: Vec<&String> = statements
        .iter()
        .filter(|s| s.starts_with("UPDATE tickets SET"))
        .collect();
    assert_eq!(
        column_writes.len(),
        1,
        "fourteen named fields must coalesce into exactly one UPDATE tickets \
         statement, got: {statements:#?}"
    );
    let combined = &column_writes[0];
    for column in [
        "type_id",
        "category_id",
        "contact_id",
        "site_id",
        "team_id",
        "contract_id",
        "sla_id",
        "scheduled_start",
        "scheduled_end",
        "estimated_hours",
        "is_billable",
        "billing_status",
        "custom_fields",
        "tags",
        "last_updated_by_id",
        "updated_at",
    ] {
        assert!(
            combined.contains(column),
            "the one UPDATE must write `{column}`: {combined}"
        );
    }
}
