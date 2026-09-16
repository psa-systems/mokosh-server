//! PMS-1215 (PSA-70 phase 5): import runs, the worker, and failure reporting.
//!
//! The phase's "done when": an import survives a server restart mid-run, a
//! failing connection is visible without reading logs, and progress is
//! pollable. The source is an in-memory fake handed to the runner through its
//! `SourceFactory`; everything else - the queue, the worker's SQL, the routes,
//! the notification - is the real code against the RLS-bound app role.

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceError, SourceGroup, SourcePhone,
    SourceResult,
};
use mokosh_server::modules::contact_sync::runs::{ContactSyncRunner, SourceFactory};
use mokosh_server::modules::notifications::NotificationsService;
use mokosh_server::utils::error::AppResult;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const CLIENTS: &str = "contactGroups/clients";

/// The scripted address book, shared between the factory and the test.
#[derive(Clone, Default)]
struct Script {
    reads: Arc<Mutex<VecDeque<SourceResult<SourceChanges>>>>,
}

impl Script {
    fn push(&self, read: SourceResult<SourceChanges>) {
        self.reads.lock().unwrap().push_back(read);
    }

    fn full(&self, contacts: Vec<SourceContact>) {
        self.push(Ok(SourceChanges {
            contacts,
            next_sync_token: Some(Uuid::new_v4().to_string()),
            was_full_resync: false,
        }));
    }
}

struct ScriptedSource(Script);

#[async_trait]
impl ContactSyncProvider for ScriptedSource {
    fn id(&self) -> &'static str {
        "google"
    }

    async fn list_groups(&self) -> SourceResult<Vec<SourceGroup>> {
        Ok(vec![SourceGroup {
            id: CLIENTS.into(),
            name: "Clients".into(),
            member_count: Some(3),
        }])
    }

    async fn changes_since(&self, _sync_token: Option<&str>) -> SourceResult<SourceChanges> {
        // An unscripted read is an account with nothing new.
        self.0.reads.lock().unwrap().pop_front().unwrap_or_else(|| {
            Ok(SourceChanges {
                contacts: vec![],
                next_sync_token: Some("quiet".into()),
                was_full_resync: false,
            })
        })
    }
}

struct ScriptedFactory(Script);

#[async_trait]
impl SourceFactory for ScriptedFactory {
    async fn source(
        &self,
        _tenant_id: TenantId,
        _connection_id: Uuid,
        _provider: &str,
    ) -> AppResult<Box<dyn ContactSyncProvider>> {
        Ok(Box::new(ScriptedSource(self.0.clone())))
    }
}

fn person(n: usize) -> SourceContact {
    SourceContact {
        external_id: format!("people/c{n}"),
        etag: Some("e1".into()),
        display_name: None,
        given_name: Some(format!("Person{n}")),
        family_name: Some("Imported".into()),
        emails: vec![format!("person{n}@clients.example")],
        phones: vec![],
        organization: None,
        title: None,
        department: None,
        group_ids: vec![CLIENTS.into()],
        photo_url: None,
        deleted: false,
    }
}

struct Fixture {
    app: common::TestApp,
    pool: PgPool,
    runner: ContactSyncRunner,
    script: Script,
    connection_id: Uuid,
    admin: String,
}

impl Fixture {
    async fn new(pool: PgPool, selected: &[&str]) -> Self {
        let (_admin_id, email, password) = common::seed_admin(&pool).await;
        let connection_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO contact_sync_connections (id, tenant_id, provider, account_email, selected_groups) \
             VALUES ($1, $2, 'google', 'ops@msp.example', $3)",
        )
        .bind(connection_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(json!(selected))
        .execute(&pool)
        .await
        .expect("seed connection");
        let app_pool = common::build_app_role_pool(&pool).await;
        let db = Database::from_pools(app_pool, pool.clone());
        let script = Script::default();
        let runner = ContactSyncRunner::new(
            db.clone(),
            Arc::new(ScriptedFactory(script.clone())),
            Some(NotificationsService::with_encryption_key(db, [7u8; 32])),
            "https://app.msp.example".into(),
        );
        let app = common::boot_rls(pool.clone()).await;
        let admin = common::login(&app, &email, &password).await;
        Self {
            app,
            pool,
            runner,
            script,
            connection_id,
            admin,
        }
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_as(&self.admin, method, path, body).await
    }

    async fn call_as(
        &self,
        token: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self
            .app
            .client
            .request(method, self.app.url(path))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("request");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// Queue a run through the API and return its id.
    async fn queue(&self) -> Uuid {
        let (status, run) = self
            .call(Method::POST, "/api/v1/integrations/contact-sync/runs", None)
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{run}");
        run["id"].as_str().unwrap().parse().unwrap()
    }

    async fn run_now(&self, run_id: Uuid) -> Value {
        self.runner
            .execute_run(TenantId::from_trusted(common::DEFAULT_TENANT_ID), run_id)
            .await
            .expect("execute run");
        self.poll(run_id).await
    }

    async fn poll(&self, run_id: Uuid) -> Value {
        let (status, run) = self
            .call(
                Method::GET,
                &format!("/api/v1/integrations/contact-sync/runs/{run_id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{run}");
        run
    }

    async fn connection(&self) -> Value {
        self.call(Method::GET, "/api/v1/integrations/contact-sync", None)
            .await
            .1
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }
}

/// Choose labels, start an import, and the worker - not the request - does
/// it. Progress is on the row the client polls.
#[sqlx::test]
async fn an_import_is_queued_by_a_request_and_done_by_the_worker(pool: PgPool) {
    let f = Fixture::new(pool, &[]).await;

    let (status, _) = f
        .call(Method::POST, "/api/v1/integrations/contact-sync/runs", None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "no label chosen yet");

    let (status, _) = f
        .call(
            Method::PUT,
            "/api/v1/integrations/contact-sync/selection",
            Some(json!({ "group_ids": ["not-a-label"] })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, connection) = f
        .call(
            Method::PUT,
            "/api/v1/integrations/contact-sync/selection",
            Some(json!({ "group_ids": [CLIENTS, CLIENTS] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{connection}");
    assert_eq!(connection["selected_groups"], json!([CLIENTS]));

    f.script.full((1..=3).map(person).collect());
    let run_id = f.queue().await;
    let queued = f.poll(run_id).await;
    assert_eq!(
        (queued["status"].as_str(), queued["trigger"].as_str()),
        (Some("queued"), Some("initial"))
    );
    let (status, _) = f
        .call(Method::POST, "/api/v1/integrations/contact-sync/runs", None)
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "one active run per connection"
    );
    assert_eq!(
        f.count("SELECT count(*) FROM contacts").await,
        0,
        "queuing imports nothing"
    );

    let summary = f.runner.tick().await.expect("tick");
    assert_eq!(summary.executed, 1);
    let run = f.poll(run_id).await;
    assert_eq!(run["status"], "completed", "{run}");
    assert_eq!(
        (
            run["created"].as_i64(),
            run["processed"].as_i64(),
            run["total"].as_i64()
        ),
        (Some(3), Some(3), Some(3))
    );
    assert!(run["finished_at"].is_string());

    let connection = f.connection().await;
    assert_eq!(connection["sync_status"], "success");
    assert_eq!(connection["latest_run"]["id"], json!(run_id));
    assert_eq!(connection["consecutive_failures"], 0);

    let (_, runs) = f
        .call(Method::GET, "/api/v1/integrations/contact-sync/runs", None)
        .await;
    assert_eq!(runs.as_array().map(Vec::len), Some(1));
}

/// A run whose process died mid-import is picked up again and lands exactly
/// once: the records the dead run applied replay as no-ops.
#[sqlx::test]
async fn a_run_interrupted_mid_import_resumes_and_lands_once(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let everyone: Vec<SourceContact> = (1..=30).map(person).collect();

    // Stop the first run part-way: the cancel is seen at the checkpoint after
    // 25 records, which is the state a crash at that point leaves behind.
    f.script.full(everyone.clone());
    let first = f.queue().await;
    sqlx::query("UPDATE contact_sync_runs SET cancel_requested_at = NOW() WHERE id = $1")
        .bind(first)
        .execute(&f.pool)
        .await
        .unwrap();
    let stopped = f.run_now(first).await;
    assert_eq!(stopped["status"], "cancelled", "{stopped}");
    assert_eq!(stopped["created"], 25);
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 25);
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_connections WHERE sync_token IS NULL")
            .await,
        1,
        "an interrupted run never moves the cursor"
    );

    // Now the crash itself: a run left `running` by a process that is gone.
    let orphan: Uuid = sqlx::query_scalar(
        "INSERT INTO contact_sync_runs (tenant_id, connection_id, trigger, status, started_at, heartbeat_at, attempts) \
         VALUES ($1, $2, 'manual', 'running', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours', 1) RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(f.connection_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    f.script.full(everyone);
    let summary = f.runner.tick().await.expect("tick after restart");
    assert_eq!((summary.recovered, summary.executed), (1, 1));

    let resumed = f.poll(orphan).await;
    assert_eq!(resumed["status"], "completed", "{resumed}");
    assert_eq!(
        resumed["created"], 5,
        "only what the dead run never reached"
    );
    assert_eq!(resumed["attempts"], 2);
    assert_eq!(
        f.count("SELECT count(*) FROM contacts").await,
        30,
        "nobody imported twice"
    );
}

/// Being rate limited is not failing: the run waits and retries by itself.
#[sqlx::test]
async fn a_rate_limited_run_waits_instead_of_failing(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    f.script.push(Err(SourceError::Throttled));
    let run_id = f.queue().await;
    let run = f.run_now(run_id).await;
    assert_eq!(run["status"], "queued", "{run}");
    assert!(run["not_before"].is_string());
    let connection = f.connection().await;
    assert_eq!(connection["sync_status"], "throttled");
    assert_eq!(connection["consecutive_failures"], 0);

    // Not claimable before its time.
    assert_eq!(f.runner.tick().await.unwrap().executed, 0);
}

/// Some records failing is reported as exactly that: what landed, what did
/// not and why, and the cursor held so the next sync retries them.
#[sqlx::test]
async fn a_partial_failure_reports_what_landed_and_what_did_not(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    sqlx::query(
        "CREATE FUNCTION refuse_broken() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.first_name = 'Person2' THEN RAISE EXCEPTION 'fixture refusal'; END IF; RETURN NEW; END $$",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER refuse_broken BEFORE INSERT ON contacts FOR EACH ROW EXECUTE FUNCTION refuse_broken()")
        .execute(&f.pool)
        .await
        .unwrap();

    f.script.full((1..=3).map(person).collect());
    let run = f.run_now(f.queue().await).await;
    assert_eq!(run["status"], "failed", "{run}");
    assert_eq!(
        (run["created"].as_i64(), run["failed_records"].as_i64()),
        (Some(2), Some(1))
    );
    assert_eq!(run["failures"][0]["external_id"], "people/c2");
    assert!(run["error"].as_str().unwrap().contains("1 of 3"), "{run}");
    let connection = f.connection().await;
    assert_eq!(connection["sync_status"], "failed");
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_connections WHERE sync_token IS NULL")
            .await,
        1
    );
}

/// A connection that keeps failing says so on the card, and somebody is told
/// once per streak rather than once per interval.
#[sqlx::test]
async fn repeated_failure_is_visible_and_notifies_once(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let notified = "SELECT count(*) FROM notifications n JOIN notification_templates t ON t.id = n.template_id \
                    WHERE t.event_type = 'contact_sync.failing'";
    for attempt in 1..=4 {
        f.script.push(Err(SourceError::Failed(
            "Google Contacts answered 500 after 5 attempts.".into(),
        )));
        let run = f.run_now(f.queue().await).await;
        assert_eq!(run["status"], "failed", "attempt {attempt}: {run}");
        let expected_mails = if attempt >= 3 { 1 } else { 0 };
        assert_eq!(f.count(notified).await, expected_mails, "attempt {attempt}");
    }
    let connection = f.connection().await;
    assert_eq!(connection["consecutive_failures"], 4);
    assert_eq!(connection["sync_status"], "failed");
    assert!(
        connection["last_error"].as_str().unwrap().contains("500"),
        "{connection}"
    );

    let (subject, body): (String, String) = sqlx::query_as(
        "SELECT n.subject, n.body FROM notifications n JOIN notification_templates t ON t.id = n.template_id \
         WHERE t.event_type = 'contact_sync.failing'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(subject.contains("ops@msp.example"), "{subject}");
    assert!(
        !body.contains("{{") && !subject.contains("{{"),
        "an unsupplied placeholder shipped: {subject} / {body}"
    );
    assert!(body.contains("3 times in a row"), "{body}");

    // One success ends the streak, and the next streak is told again.
    let run = f.run_now(f.queue().await).await;
    assert_eq!(run["status"], "completed");
    let connection = f.connection().await;
    assert_eq!(connection["consecutive_failures"], 0);
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_connections WHERE failure_notified_at IS NULL")
            .await,
        1
    );
}

/// The review queue lists a record with its candidates, and each answer is
/// kept: a link fills only what was empty, a create makes the contact, a skip
/// is never asked again.
#[sqlx::test]
async fn the_review_queue_lists_and_resolves(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let grace = Uuid::new_v4();
    sqlx::query("INSERT INTO contacts (id, tenant_id, first_name, last_name) VALUES ($1, $2, 'Grace', 'Hopper')")
        .bind(grace)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO contact_phones (tenant_id, contact_id, phone_type, number, is_primary) \
         VALUES ($1, $2, 'work', '+14155550000', TRUE)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(grace)
    .execute(&f.pool)
    .await
    .unwrap();
    let phone = |n: &str| SourcePhone {
        number: n.into(),
        canonical: None,
        label: Some("work".into()),
        is_primary: true,
    };
    let mut linked = person(1);
    linked.emails = vec!["grace@navy.example".into()];
    linked.title = Some("Rear Admiral".into());
    linked.phones = vec![phone("+14155550000")];
    let mut created = person(2);
    created.phones = vec![phone("+1 415 555 0000")];
    let mut skipped = person(3);
    skipped.phones = vec![phone("+14155550000")];
    f.script
        .full(vec![linked.clone(), created.clone(), skipped.clone()]);
    let run = f.run_now(f.queue().await).await;
    assert_eq!(run["queued_for_review"], 3, "{run}");

    let (status, queue) = f
        .call(
            Method::GET,
            "/api/v1/integrations/contact-sync/review-queue",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = queue.as_array().expect("items");
    assert_eq!(items.len(), 3, "{queue}");
    assert_eq!(items[0]["candidates"][0]["contact_id"], json!(grace));
    assert_eq!(items[0]["candidates"][0]["match_reason"], "phone");
    assert!(items[0]["source"]["first_name"].is_string());

    let resolve = |body: Value| {
        f.call(
            Method::POST,
            "/api/v1/integrations/contact-sync/review-queue/resolve",
            Some(body),
        )
    };
    let (status, _) = resolve(
        json!({ "action": "link", "external_id": "people/c1", "contact_id": Uuid::new_v4() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "only a proposed contact can be linked"
    );
    let (status, body) =
        resolve(json!({ "action": "link", "external_id": "people/c1", "contact_id": grace })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = resolve(json!({ "action": "create", "external_id": "people/c2" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_contact: Uuid = body["contact_id"].as_str().unwrap().parse().unwrap();
    let (status, _) = resolve(json!({ "action": "skip", "external_id": "people/c3" })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = resolve(json!({ "action": "skip", "external_id": "people/c3" })).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an answered record is no longer in the queue"
    );

    let (first, last, email, title): (String, String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT first_name, last_name, email, title FROM contacts WHERE id = $1")
            .bind(grace)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        (first.as_str(), last.as_str()),
        ("Grace", "Hopper"),
        "a link never overwrites"
    );
    assert_eq!(
        email.as_deref(),
        Some("grace@navy.example"),
        "a link fills what was empty"
    );
    assert_eq!(title.as_deref(), Some("Rear Admiral"));
    assert_eq!(
        f.count(&format!("SELECT count(*) FROM contact_sync_links WHERE contact_id = '{new_contact}' AND origin = 'created'")).await,
        1
    );
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_candidates WHERE status = 'open'")
            .await,
        0
    );

    // The same records again: nothing re-queued, nothing re-created.
    f.script.full(vec![linked, created, skipped]);
    let again = f.run_now(f.queue().await).await;
    assert_eq!(
        (
            again["queued_for_review"].as_i64(),
            again["created"].as_i64()
        ),
        (Some(0), Some(0)),
        "{again}"
    );
    assert_eq!(again["skipped"], 1, "the skipped record stays answered");
    let connection = f.connection().await;
    assert_eq!(connection["open_reviews"], 0);
}

/// A cancel stops a queued run, and a disconnect stops whatever is in flight
/// without it counting as a failure.
#[sqlx::test]
async fn cancel_and_disconnect_stop_runs(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let run_id = f.queue().await;
    let cancel = format!("/api/v1/integrations/contact-sync/runs/{run_id}/cancel");
    let (status, run) = f.call(Method::POST, &cancel, None).await;
    assert_eq!(status, StatusCode::OK, "{run}");
    assert_eq!(run["status"], "cancelled");
    assert_eq!(
        f.call(Method::POST, &cancel, None).await.0,
        StatusCode::CONFLICT
    );

    let next = f.queue().await;
    let (status, _) = f
        .call(
            Method::POST,
            "/api/v1/integrations/contact-sync/google/disconnect",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        f.count(&format!(
            "SELECT count(*) FROM contact_sync_runs WHERE id = '{next}' AND status = 'cancelled'"
        ))
        .await,
        1
    );
    assert_eq!(f.runner.tick().await.unwrap().executed, 0);
    assert_eq!(
        f.count("SELECT consecutive_failures::bigint FROM contact_sync_connections")
            .await,
        0
    );
}

/// The worker queues a connection past its interval, and leaves alone one
/// that cannot succeed or has nothing selected.
#[sqlx::test]
async fn the_worker_schedules_only_connections_that_are_due_and_able(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let set = |sql: &'static str| {
        let pool = f.pool.clone();
        async move { sqlx::query(sql).execute(&pool).await.unwrap() }
    };

    set("UPDATE contact_sync_connections SET last_sync_at = NOW() - INTERVAL '10 minutes', sync_status = 'success'").await;
    assert_eq!(f.runner.tick().await.unwrap().scheduled, 0, "not due yet");

    set("UPDATE contact_sync_connections SET last_sync_at = NOW() - INTERVAL '2 hours', sync_status = 'reconnect_required'").await;
    assert_eq!(
        f.runner.tick().await.unwrap().scheduled,
        0,
        "a revoked grant cannot succeed"
    );

    set("UPDATE contact_sync_connections SET sync_status = 'success', selected_groups = '[]'")
        .await;
    assert_eq!(
        f.runner.tick().await.unwrap().scheduled,
        0,
        "nothing selected"
    );

    set("UPDATE contact_sync_connections SET selected_groups = '[\"contactGroups/clients\"]'")
        .await;
    let summary = f.runner.tick().await.unwrap();
    assert_eq!((summary.scheduled, summary.executed), (1, 1));
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_runs WHERE trigger = 'scheduled' AND status = 'completed'").await,
        1
    );
}

/// Starting imports and choosing labels are an admin's; watching progress and
/// answering the queue are any staff member's.
#[sqlx::test]
async fn admins_start_imports_and_staff_follow_them(pool: PgPool) {
    let f = Fixture::new(pool, &[CLIENTS]).await;
    let run_id = f.queue().await;
    let (_id, email, password) = common::seed_user(
        &f.pool,
        common::DEFAULT_TENANT_ID,
        "tech@contact-sync.example",
        "technician",
    )
    .await;
    let tech = common::login(&f.app, &email, &password).await;

    for (method, path, body) in [
        (
            Method::POST,
            "/api/v1/integrations/contact-sync/runs".to_string(),
            None,
        ),
        (
            Method::PUT,
            "/api/v1/integrations/contact-sync/selection".to_string(),
            Some(json!({ "group_ids": [CLIENTS] })),
        ),
        (
            Method::POST,
            format!("/api/v1/integrations/contact-sync/runs/{run_id}/cancel"),
            None,
        ),
        (
            Method::GET,
            "/api/v1/integrations/contact-sync/groups".to_string(),
            None,
        ),
    ] {
        let (status, _) = f.call_as(&tech, method.clone(), &path, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }
    for path in [
        format!("/api/v1/integrations/contact-sync/runs/{run_id}"),
        "/api/v1/integrations/contact-sync/runs".to_string(),
        "/api/v1/integrations/contact-sync/review-queue".to_string(),
    ] {
        let (status, _) = f.call_as(&tech, Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
}
