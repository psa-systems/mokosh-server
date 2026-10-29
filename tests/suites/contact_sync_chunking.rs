//! PMS-1303: `ContactSyncEngine::run` applies records in chunks that share
//! one `begin_with_tenant` transaction instead of opening one per record.
//!
//! This file pins the chunk boundary with a `sqlx::query` tracing recorder
//! (same shape as `assets_bulk_create_query_budget.rs`): the subscriber is
//! process-global, so this file holds exactly ONE test on purpose. The
//! assertion counts `BEGIN` events during a 500-record sync and compares
//! them against `CHUNK_SIZE`, so a regression that re-opens one
//! transaction per record (the pre-PMS-1303 shape) fails loud.

use crate::common;

use mokosh_test::mokosh_test;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceEmail, SourceGroup, SourceResult,
};
use mokosh_server::modules::contact_sync::sync::ContactSyncEngine;

const CLIENTS: &str = "contactGroups/clients";

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

/// sqlx 0.8 records string field values with the Debug formatter, so the
/// captured text arrives quoted and escape-sequenced. Normalising with
/// `split_whitespace` collapses newlines and makes a `contains("BEGIN")`
/// check tolerate the escape artefact; see
/// `assets_bulk_create_query_budget.rs` for the longer form of this note.
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

/// A fake address book that returns one scripted read.
struct FakeSource {
    reads: Mutex<VecDeque<SourceResult<SourceChanges>>>,
}

#[async_trait]
impl ContactSyncProvider for FakeSource {
    fn id(&self) -> &'static str {
        "google"
    }

    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>> {
        Ok(vec![SourceGroup {
            id: CLIENTS.into(),
            name: "Clients".into(),
            member_count: None,
        }])
    }

    async fn changes_since(&self, _: Option<&str>) -> SourceResult<SourceChanges> {
        self.reads
            .lock()
            .unwrap()
            .pop_front()
            .expect("the fixture scripted no further read")
    }
}

/// A synthetic contact with a unique email (so every record is a clean
/// `Plan::Create` and the write path is exercised end-to-end).
fn person(index: usize) -> SourceContact {
    let external_id = format!("people/{index:04}");
    let given = format!("Chunk{index:04}");
    let family = "Record".to_string();
    SourceContact {
        external_id,
        etag: Some(format!("etag-{index:04}")),
        display_name: Some(format!("{given} {family}")),
        given_name: Some(given.clone()),
        family_name: Some(family.clone()),
        emails: vec![SourceEmail {
            address: format!("chunk-{index:04}@example.invalid"),
            label: Some("work".into()),
        }],
        phones: vec![],
        organization: None,
        title: None,
        department: None,
        group_ids: vec![CLIENTS.into()],
        note: None,
        photo: None,
        dropped_properties: vec![],
        deleted: false,
    }
}

/// 500 is five times the pre-PMS-1303 CHECKPOINT_EVERY, chosen so the
/// chunk count is not 1 (a 25-record sync could land in a single chunk
/// and hide a regression that reverted to per-record transactions).
const RECORDS: usize = 500;

/// The per-record SAVEPOINT emits two extra `sqlx::query` events on the
/// success path (`SAVEPOINT ...` + `RELEASE SAVEPOINT ...`). The chunk
/// transaction itself emits one `BEGIN` and one `SET LOCAL ...` on open
/// plus one `COMMIT` on close. Those three bookkeeping statements per
/// chunk are the sub-linear floor the test asserts against.
#[mokosh_test]
async fn a_500_record_sync_shares_one_tx_per_chunk(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    // sqlx 0.8's `tracing_dynamic_enabled!` check consults the subscriber
    // for the sqlx::query target's level before formatting the event; a
    // bare `registry()` subscriber with no filter answers "disabled" at
    // Debug (the default sqlx statements_level), so no event ever reaches
    // RecordingLayer. An EnvFilter that enables sqlx::query=debug flips
    // that check true and the events arrive.
    let filter = tracing_subscriber::EnvFilter::new("sqlx::query=debug");
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(filter)
            .with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let _ = common::seed_admin(&pool).await;

    let connection_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_sync_connections \
         (id, tenant_id, provider, account_email, selected_groups) \
         VALUES ($1, $2, 'google', 'ops@msp.example', $3)",
    )
    .bind(connection_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(serde_json::json!([CLIENTS]))
    .execute(&pool)
    .await
    .expect("seed connection");

    let records: Vec<SourceContact> = (0..RECORDS).map(person).collect();
    let source = FakeSource {
        reads: Mutex::new(VecDeque::from([Ok(SourceChanges {
            contacts: records,
            next_sync_token: Some("tok-after-500".into()),
            was_full_resync: true,
        })])),
    };

    let app_pool = common::build_app_role_pool(&pool).await;
    let db = Database::from_pools(app_pool, pool.clone());
    let engine = ContactSyncEngine::new(db);

    recorder.armed.store(true, Ordering::SeqCst);
    let report = engine
        .run(
            TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            connection_id,
            &source,
        )
        .await
        .expect("sync should succeed");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(
        report.created, RECORDS as u32,
        "every synthetic record should land as a Create"
    );
    assert_eq!(report.failed, 0, "no record should have failed");

    let statements = recorder.take();
    // sqlx's PgConnection::begin does not emit a user-visible `BEGIN`
    // sqlx::query event (the protocol-level BEGIN is sent on the simple
    // query path without going through Executor::execute). What IS
    // emitted immediately after every `begin_with_tenant` is the tenant
    // GUC `SELECT set_config('app.current_tenant', $1, true)`, so count
    // that to count transactions on the tenant-scoped pool.
    let begins = statements
        .iter()
        .filter(|s| s.contains("set_config('app.current_tenant'"))
        .count();

    // The chunk size is 25 (see sync.rs's `CHUNK_SIZE`), so 500 records
    // land in 20 chunks. The absent-sweep ran against a full-read fixture
    // that linked every record, so no `flag_deleted_in` chunk fired. The
    // whole sync therefore opens 20 chunk transactions. Allow a small
    // headroom (set_status at the top of the run, finish at the bottom)
    // and compare the ceiling against "once per record".
    assert!(
        begins <= 40,
        "a 500-record sync should open at most 40 transactions \
         (CHUNK_SIZE=25 chunks + a handful for status/finish), got {begins}"
    );
    assert!(
        begins >= 15,
        "a 500-record sync must still open at least one tx per 25-record \
         chunk; got {begins} which is suspiciously low (did the apply \
         path get skipped?)"
    );
}
