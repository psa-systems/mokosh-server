//! PMS-782 (finding F8): the transaction and statement budget of
//! `NotificationsService::dispatch`, pinned as a regression test.
//!
//! `dispatch` used to open a `begin_with_tenant` transaction per rule (for the
//! template read), per preference batch, and per row it inserted, so a rule
//! with C channels and R recipients cost `2 + C * R` transactions - each one a
//! BEGIN, a `set_config`, the statement and a COMMIT - to write `C * R` rows.
//! It also re-rendered the same template once per channel. `dispatch` is
//! awaited inline on request paths (`TicketService::add_note`), so the caller
//! paid every one of those round trips.
//!
//! It now runs in exactly one transaction, inserts one statement per (rule,
//! channel, recipient kind), and renders once per rule.
//!
//! The counts come from a `tracing` subscriber that records `sqlx::query`
//! events, the in-process equivalent of Postgres `log_statement=all` (the
//! `tests/contract_sweep_query_budget.rs` pattern). sqlx issues `BEGIN` on the
//! raw protocol rather than through the logging executor, so the transaction
//! count is read off the two statements that ARE logged and are one-per-
//! transaction: the `set_config('app.current_tenant', ...)` that
//! `Database::begin_with_tenant` runs, and the matching `COMMIT`.
//!
//! This file holds exactly ONE test on purpose: the subscriber is
//! process-global, so a second test running concurrently would count its
//! statements as well.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::notifications::{NotificationsService, RENDER_TRACE_TARGET};
use mokosh_server::Database;

/// Statements and render events observed while [`Recorder::armed`] is set.
#[derive(Default)]
struct Recorder {
    armed: AtomicBool,
    statements: Mutex<Vec<String>>,
    renders: Mutex<usize>,
}

impl Recorder {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.statements.lock().expect("statement log"))
    }

    fn render_count(&self) -> usize {
        *self.renders.lock().expect("render count")
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
        if !self.0.armed.load(Ordering::SeqCst) {
            return;
        }
        match event.metadata().target() {
            RENDER_TRACE_TARGET => {
                *self.0.renders.lock().expect("render count") += 1;
            }
            "sqlx::query" => {
                let mut visitor = SqlVisitor::default();
                event.record(&mut visitor);
                // sqlx leaves `db.statement` empty for a single-line
                // statement and puts the text in `summary`; a multi-line one
                // populates both.
                let sql = visitor
                    .statement
                    .filter(|s| !s.trim().is_empty())
                    .or(visitor.summary)
                    .unwrap_or_else(|| "<no sql field>".to_string());
                self.0
                    .statements
                    .lock()
                    .expect("statement log")
                    .push(sql.split_whitespace().collect::<Vec<_>>().join(" "));
            }
            _ => {}
        }
    }
}

/// Recipients on the rule, over both channels. Large enough that a
/// per-recipient transaction would be unmistakable against the fixed cost.
const RECIPIENT_USERS: usize = 3;
const RECIPIENT_EMAILS: usize = 2;

#[sqlx::test]
async fn one_dispatch_is_one_transaction(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let tenant_id = common::DEFAULT_TENANT_ID;
    let event_type = "test.dispatch_budget";

    // Three real users so the fan-out has user rows to write; none of them has
    // a preference row, so every one accepts every channel (PMS-195 default).
    let mut user_ids: Vec<Uuid> = Vec::new();
    for i in 0..RECIPIENT_USERS {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, role, status)
               VALUES ($1, $2, $3, 'x', 'Budget', 'User', 'technician', 'active')"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(format!("budget-{i}@example.test"))
        .execute(&pool)
        .await
        .expect("seed recipient user");
        user_ids.push(id);
    }
    let emails: Vec<String> = (0..RECIPIENT_EMAILS)
        .map(|i| format!("standalone-{i}@example.test"))
        .collect();

    let template_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO notification_templates
               (id, tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
           VALUES ($1, $2, 'Budget Template', $3, 'email', $4, $5, $6, TRUE)"#,
    )
    .bind(template_id)
    .bind(tenant_id)
    .bind(event_type)
    .bind("Subject for {{display_name}}")
    .bind("Body for {{display_name}}")
    .bind("<p>Body for {{display_name}}</p>")
    .execute(&pool)
    .await
    .expect("seed template");

    // One rule, two channels: the shape that used to render the same template
    // twice and open a transaction per (channel, recipient).
    sqlx::query(
        r#"INSERT INTO notification_rules
               (id, tenant_id, name, event_type, channels, recipients, template_id, is_active)
           VALUES ($1, $2, 'Budget Rule', $3, ARRAY['email', 'in_app']::VARCHAR(20)[], $4, $5, TRUE)"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(event_type)
    .bind(serde_json::json!({
        "user_ids": user_ids.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
        "emails": emails,
    }))
    .bind(template_id)
    .execute(&pool)
    .await
    .expect("seed rule");

    let svc =
        NotificationsService::with_encryption_key(Database::from_pool(pool.clone()), [7u8; 32]);

    recorder.armed.store(true, Ordering::SeqCst);
    let fanout = svc
        .dispatch(
            TenantId::from_trusted(tenant_id),
            event_type,
            &serde_json::json!({"display_name": "Budget"}),
        )
        .await
        .expect("dispatch");
    recorder.armed.store(false, Ordering::SeqCst);

    // in_app carries no standalone addresses, so the fan-out is
    // (users + emails) on `email` plus users on `in_app`.
    let expected_rows = (RECIPIENT_USERS + RECIPIENT_EMAILS + RECIPIENT_USERS) as u64;
    assert_eq!(
        fanout, expected_rows,
        "the measured dispatch must still queue every recipient",
    );
    let queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notifications WHERE template_id = $1")
            .bind(template_id)
            .fetch_one(&pool)
            .await
            .expect("count queued rows");
    assert_eq!(
        queued as u64, expected_rows,
        "rows on disk must match the count"
    );

    let statements = recorder.take();

    // AC: `dispatch` calls `begin_with_tenant` exactly once and commits once.
    // One `set_config` = one `begin_with_tenant`; one COMMIT = one committed
    // transaction. Under `log_statement=all` this is the single BEGIN.
    let begins = statements
        .iter()
        .filter(|s| s.starts_with("SELECT set_config('app.current_tenant'"))
        .count();
    assert_eq!(
        begins, 1,
        "a dispatch must open exactly one tenant transaction, got: {statements:#?}"
    );
    let commits = statements.iter().filter(|s| *s == "COMMIT").count();
    assert_eq!(
        commits, 1,
        "a dispatch must commit exactly once, got: {statements:#?}"
    );

    // AC: recipient rows are inserted with at most two statements per (rule,
    // channel), independent of recipient count. Two channels here: `email`
    // (user rows + standalone rows = 2 statements) and `in_app` (user rows
    // only = 1).
    let inserts: Vec<&String> = statements
        .iter()
        .filter(|s| s.starts_with("INSERT INTO notifications"))
        .collect();
    assert_eq!(
        inserts.len(),
        3,
        "expected 2 inserts for the email channel and 1 for in_app, got: {inserts:#?}"
    );
    assert!(
        inserts.iter().all(|s| s.contains("UNNEST")),
        "each insert must be the batched UNNEST form: {inserts:#?}"
    );

    // AC: `render_template` runs at most three times per rule (subject, text
    // body, HTML body), not three times per channel.
    assert_eq!(
        recorder.render_count(),
        3,
        "one rule with a subject, a text body and an HTML body renders three \
         times whatever its channel count",
    );

    // The whole statement budget, so a new per-row read cannot creep back in
    // unnoticed: the rule read, the template read, the preference read, the
    // three inserts, the set_config and the COMMIT.
    assert_eq!(
        statements.len(),
        8,
        "unexpected statement budget for one dispatch: {statements:#?}"
    );
}
