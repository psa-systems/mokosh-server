//! PMS-1380 (F2): `vcard_files` lists a page of uploads with three queries in
//! one transaction (ids, file metadata batch, latest-run batch), not one
//! transaction and two queries per upload.
//!
//! The obvious implementation is a loop calling `vcard_file` once per id,
//! which is exactly what shipped first: a full page of uploads cost up to
//! one transaction and two queries per row. This file pins the batched shape
//! with the same `tracing`-subscriber query-count pattern as
//! `tests/contact_hydration_query_budget.rs`, calling the service directly
//! (not through the HTTP route) so the auth middleware's own queries do not
//! pollute the count. It holds exactly ONE test for the same reason the
//! hydration file does: the subscriber is process-global, so a second test
//! running concurrently would count its statements too.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::db::Database;
use mokosh_server::modules::audit::AuditCtx;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::ContactSyncService;
use mokosh_server::secrets::{DatabaseSecretProvider, SecretProvider};

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

fn card(body: &str) -> String {
    format!("BEGIN:VCARD\r\nVERSION:3.0\r\n{body}END:VCARD\r\n")
}

/// Uploads on the measured page: enough that a per-row read shows up clearly
/// against the fixed per-page cost.
const UPLOADS: usize = 5;

#[sqlx::test]
async fn a_vcard_upload_page_reads_files_and_runs_each_once(pool: PgPool) {
    // Installed before any `common::` call, because several of them
    // (`seed_admin`, `storage_root`) call `init_tracing`, which installs a
    // subscriber of its own via `try_init` the first time anything calls it
    // in this process; `try_init` silently no-ops once this one has already
    // claimed the global default, but the reverse is not true.
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    common::storage_root();
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let db = Database::from_pool(pool.clone());
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(DatabaseSecretProvider::new(db.clone(), [0u8; 32]));
    let service = ContactSyncService::new(db, secrets, None, "https://app.msp.example".to_string());
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let ctx = AuditCtx::system(common::DEFAULT_TENANT_ID);

    let mut file_ids = Vec::with_capacity(UPLOADS);
    for i in 0..UPLOADS {
        let bytes = card(&format!(
            "FN:Person {i}\r\nEMAIL:person{i}@budget.example\r\n"
        ))
        .into_bytes();
        let uploaded = service
            .upload_vcard(tenant, Some(&format!("upload-{i}.vcf")), bytes, &ctx)
            .await
            .expect("upload");
        file_ids.push(uploaded.file.id);
    }

    // Two runs on the first upload, so the latest-run batch has to pick the
    // newer one rather than merely proving it can join at all.
    let connection_id: Uuid =
        sqlx::query_scalar("SELECT connection_id FROM contact_import_files WHERE id = $1")
            .bind(file_ids[0])
            .fetch_one(&pool)
            .await
            .expect("connection id");
    let older_run = Uuid::new_v4();
    let newer_run = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_sync_runs \
         (id, tenant_id, connection_id, import_file_id, trigger, status, created_at) \
         VALUES ($1, $2, $3, $4, 'manual', 'failed', NOW() - INTERVAL '1 hour')",
    )
    .bind(older_run)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(connection_id)
    .bind(file_ids[0])
    .execute(&pool)
    .await
    .expect("older run");
    sqlx::query(
        "INSERT INTO contact_sync_runs \
         (id, tenant_id, connection_id, import_file_id, trigger, status, created_at) \
         VALUES ($1, $2, $3, $4, 'manual', 'completed', NOW())",
    )
    .bind(newer_run)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(connection_id)
    .bind(file_ids[0])
    .execute(&pool)
    .await
    .expect("newer run");

    recorder.armed.store(true, Ordering::SeqCst);
    let files = service.vcard_files(tenant, 20).await.expect("list uploads");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(files.len(), UPLOADS, "the page covers every upload");
    // Newest first, matching `uploaded_at DESC`.
    assert_eq!(files[0].id, file_ids[UPLOADS - 1]);
    assert_eq!(files[UPLOADS - 1].id, file_ids[0]);
    assert_eq!(
        files[UPLOADS - 1]
            .latest_run
            .as_ref()
            .expect("latest run")
            .id,
        newer_run,
        "the newer run wins, proving the batch is per-file rather than any row"
    );

    let statements = recorder.take();
    for (needle, label) in [
        // The aliased join form the batched file-metadata read uses; the
        // id-list query also names `contact_import_files` but with no
        // alias, so matching the bare table name here would double-count
        // it against this read.
        ("FROM contact_import_files f", "file metadata"),
        ("contact_sync_runs", "latest run"),
    ] {
        let reads: Vec<&String> = statements
            .iter()
            .filter(|s| s.starts_with("SELECT") && s.contains(needle))
            .collect();
        assert_eq!(
            reads.len(),
            1,
            "reading {label} for {UPLOADS} uploads must read it exactly once \
             (N+1 regression), got: {reads:#?}"
        );
        assert!(
            reads[0].contains("ANY("),
            "the {label} read must be the batched `= ANY($n)` form: {reads:#?}"
        );
    }
    // The id-list query is the third and only other SELECT touching these
    // tables: three queries total, not one per row.
    let all_reads: Vec<&String> = statements
        .iter()
        .filter(|s| s.starts_with("SELECT"))
        .collect();
    assert_eq!(
        all_reads.len(),
        3,
        "listing {UPLOADS} uploads must issue exactly 3 SELECTs, got: {all_reads:#?}"
    );
}
