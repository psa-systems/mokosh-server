//! PMS-1517: `bulk_create_assets`'s response-fetch step issues one SELECT
//! regardless of batch size.
//!
//! The write loop inside `bulk_create_assets` runs its own INSERTs under one
//! transaction; the regression we care about is the follow-up read that
//! rebuilds the response. Before the fix, it called `get_asset` once per
//! created id, so an N-serial batch issued N serialized reads. The fix fans
//! one `SELECT ... WHERE a.id = ANY($2)` with the same join shape, so the
//! batched read's query count is 1 regardless of N.
//!
//! The subscriber is process-global, so this file holds exactly one test on
//! purpose (same reason as `contact_hydration_query_budget.rs`).

use crate::common;

use mokosh_test::mokosh_test;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::modules::assets::{AssetsService, BulkCreateAssetsRequest, BulkSerial};
use mokosh_server::modules::auth::TenantId;
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

#[derive(Default)]
struct SqlVisitor {
    statement: Option<String>,
    summary: Option<String>,
}

impl Visit for SqlVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "db.statement" {
            self.statement = Some(format!("{value:?}"));
        } else if field.name() == "summary" {
            self.summary = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "db.statement" {
            self.statement = Some(value.to_string());
        } else if field.name() == "summary" {
            self.summary = Some(value.to_string());
        }
    }
}

struct RecordingLayer(Arc<Recorder>);

impl<S: tracing::Subscriber> Layer<S> for RecordingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if !self.0.armed.load(Ordering::SeqCst) {
            return;
        }
        if event.metadata().target() != "sqlx::query" {
            return;
        }
        let mut v = SqlVisitor::default();
        event.record(&mut v);
        // sqlx 0.8 wraps `db.statement` for a multi-line SQL in a leading
        // `\n\n` and a trailing `\n` (sqlx-core-0.8.6/src/logger.rs:109),
        // so a stored statement starts with "\n\n" and the response-fetch
        // SELECT below fails a `starts_with("SELECT")` filter. Normalise
        // the whitespace at push time, matching contact_hydration_query_budget.rs.
        // When the SQL is a one-liner (`summary == self.sql`) sqlx sets
        // `db.statement` to the empty string and only `summary` is useful;
        // the `.or(v.summary)` fallback handles that.
        let text = v
            .statement
            .filter(|s| !s.is_empty())
            .or(v.summary)
            .unwrap_or_default();
        if !text.is_empty() {
            let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
            self.0
                .statements
                .lock()
                .expect("statement log")
                .push(normalised);
        }
    }
}

async fn seed_company(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'BudgetCo')")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_asset_type(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO asset_types (id, tenant_id, name, is_active) \
         VALUES ($1, $2, 'Laptop', TRUE)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(pool)
    .await
    .expect("seed asset type");
    id
}

async fn seed_asset_model(pool: &PgPool, asset_type_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO asset_models \
            (id, tenant_id, manufacturer, model, asset_type_id, source) \
         VALUES ($1, $2, 'Dell', 'Latitude 5450', $3, 'tenant_authored')",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(asset_type_id)
    .execute(pool)
    .await
    .expect("seed asset model");
    id
}

/// Enough serials that an N+1 fetch stands out clearly against the fixed
/// INSERT cost.
const SERIALS: usize = 5;

#[mokosh_test]
async fn bulk_create_fetches_the_response_in_one_select(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    // `bulk_create_assets` writes one `asset_audit_log` row per inserted
    // asset with `performed_by_id = performer`, which has an FK to `users.id`.
    // The seeded admin's id is the one row we know exists in this fresh
    // template; a `Uuid::new_v4()` here would fail the FK constraint.
    let (performer_id, _, _) = common::seed_admin(&pool).await;
    let company_id = seed_company(&pool).await;
    let asset_type_id = seed_asset_type(&pool).await;
    let model_id = seed_asset_model(&pool, asset_type_id).await;

    let svc = AssetsService::with_encryption_key(Database::from_pool(pool.clone()), [0u8; 32]);
    let tenant = TenantId::from_trusted(common::DEFAULT_TENANT_ID);
    let request = BulkCreateAssetsRequest {
        template_id: None,
        asset_model_id: Some(model_id),
        company_id,
        site_id: None,
        assigned_user_id: None,
        department: None,
        purchase_date: None,
        purchase_price: None,
        installed_date: None,
        serials: (0..SERIALS)
            .map(|i| BulkSerial {
                serial_number: format!("QA-{i:03}"),
                name: None,
                asset_tag: None,
                hostname: None,
                mac_address: None,
                ip_address: None,
            })
            .collect(),
    };

    recorder.armed.store(true, Ordering::SeqCst);
    let created = svc
        .bulk_create_assets(tenant, performer_id, &request)
        .await
        .expect("bulk create");
    recorder.armed.store(false, Ordering::SeqCst);

    assert_eq!(created.len(), SERIALS, "every serial has a response row");

    // The response-fetch query joins `assets a` to `asset_types`, `companies`,
    // `users` and `contacts`, and (post PMS-1517) matches rows by
    // `a.id = ANY(...)`. Any statement matching that join shape is the batched
    // fetch; count how many landed. A `starts_with("SELECT")` prefix check is
    // deliberately NOT used: `tracing` records string field values with the
    // Debug formatter, so sqlx's `db.statement` arrives as a quoted, escaped
    // string that starts with `"` (and the `summary` fallback carries the same
    // escaping). The two contains() checks together are unique to the response
    // fetch in `bulk_create_assets` already: nothing else in the write path
    // joins `assets a` to `asset_types`.
    let statements = recorder.take();
    let response_fetch: Vec<&String> = statements
        .iter()
        .filter(|s| s.contains("FROM assets a") && s.contains("LEFT JOIN asset_types"))
        .collect();
    assert_eq!(
        response_fetch.len(),
        1,
        "bulk-create must rebuild its response in ONE batched SELECT regardless of \
         batch size (N+1 regression); got {} matching queries: {response_fetch:#?}",
        response_fetch.len()
    );
    // The one SELECT uses the batched predicate, not a single-id lookup.
    assert!(
        response_fetch[0].contains("ANY("),
        "the batched fetch binds `a.id = ANY($2)`, not a per-row lookup: {}",
        response_fetch[0]
    );
}
