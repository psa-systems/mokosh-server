//! PMS-1214 (PSA-70 phase 4): the parts that decide whether a person trusts
//! the integration.
//!
//! An edit in Mokosh survives the next sync, a deletion in Google changes no
//! Mokosh field, a disconnect keeps every contact, an unlink stays unlinked,
//! and a person's imported data can be removed without coming back. Each is
//! driven through the HTTP routes a client uses, with the sync run directly
//! against an in-memory source, and each leaves an audit row.

mod common;

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::provider::{
    ContactSyncProvider, SourceChanges, SourceContact, SourceGroup, SourceResult,
};
use mokosh_server::modules::contact_sync::sync::{ContactSyncEngine, SyncReport};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const CLIENTS: &str = "contactGroups/clients";

struct FakeSource {
    reads: Mutex<VecDeque<SourceChanges>>,
}

impl FakeSource {
    fn new() -> Self {
        Self {
            reads: Mutex::new(VecDeque::new()),
        }
    }

    /// Script the next read.
    fn next(&self, contacts: Vec<SourceContact>, full: bool) -> &Self {
        self.reads.lock().unwrap().push_back(SourceChanges {
            contacts,
            next_sync_token: Some(Uuid::new_v4().to_string()),
            was_full_resync: full,
        });
        self
    }
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

    async fn changes_since(&self, _sync_token: Option<&str>) -> SourceResult<SourceChanges> {
        Ok(self
            .reads
            .lock()
            .unwrap()
            .pop_front()
            .expect("the fixture scripted no further read"))
    }
}

fn person(external_id: &str, etag: &str, given: &str, email: &str) -> SourceContact {
    SourceContact {
        external_id: external_id.into(),
        etag: Some(etag.into()),
        display_name: Some(given.into()),
        given_name: Some(given.into()),
        family_name: Some("Person".into()),
        emails: vec![email.into()],
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
    db: Database,
    connection_id: Uuid,
    admin_id: Uuid,
    admin: String,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        let (admin_id, email, password) = common::seed_admin(&pool).await;
        let connection_id = seed_connection(&pool).await;
        let app_pool = common::build_app_role_pool(&pool).await;
        let app = common::boot_rls(pool.clone()).await;
        let admin = common::login(&app, &email, &password).await;
        Self {
            app,
            db: Database::from_pools(app_pool, pool.clone()),
            pool,
            connection_id,
            admin_id,
            admin,
        }
    }

    async fn sync(&self, source: &FakeSource) -> SyncReport {
        self.sync_connection(self.connection_id, source).await
    }

    async fn sync_connection(&self, connection_id: Uuid, source: &FakeSource) -> SyncReport {
        ContactSyncEngine::new(self.db.clone())
            .run(
                TenantId::from_trusted(common::DEFAULT_TENANT_ID),
                connection_id,
                source,
            )
            .await
            .expect("sync")
    }

    async fn linked_contact(&self, external_id: &str) -> Uuid {
        sqlx::query_scalar(
            "SELECT contact_id FROM contact_sync_links WHERE external_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(external_id)
        .fetch_one(&self.pool)
        .await
        .expect("a link for the record")
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call_as(&self.admin, method, path, body).await
    }

    async fn call_as(
        &self,
        token: &str,
        method: reqwest::Method,
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
        let body = response.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    async fn column(&self, contact_id: Uuid, column: &str) -> Option<String> {
        sqlx::query_scalar(&format!(
            "SELECT {column}::text FROM contacts WHERE id = $1"
        ))
        .bind(contact_id)
        .fetch_one(&self.pool)
        .await
        .expect("contact column")
    }
}

async fn seed_connection(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_sync_connections (id, tenant_id, provider, account_email, selected_groups) \
         VALUES ($1, $2, 'google', 'ops@msp.example', $3)",
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(json!([CLIENTS]))
    .execute(pool)
    .await
    .expect("seed connection");
    id
}

/// PSA-70 H: the edit is what locks, the next sync leaves it, and a release
/// hands the field back to the source.
#[sqlx::test]
async fn an_edit_locks_the_field_and_survives_the_next_sync(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    let mut ada = person("people/ada", "e1", "Ada", "ada@acme.example");
    ada.title = Some("Analyst".into());
    source.next(vec![ada.clone()], false);
    f.sync(&source).await;
    let contact = f.linked_contact("people/ada").await;

    let (status, _) = f
        .call(
            reqwest::Method::PUT,
            &format!("/api/v1/contacts/contacts/{contact}"),
            Some(json!({ "title": "CTO" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, provenance) = f
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/contacts/contacts/{contact}/sync"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let locks = provenance["locks"].as_array().expect("locks");
    assert_eq!(locks.len(), 1, "only the edited field locks: {provenance}");
    assert_eq!(locks[0]["field"], "title");
    assert_eq!(locks[0]["locked_by_user_id"], json!(f.admin_id));
    assert_eq!(provenance["links"][0]["origin"], "created");
    assert_eq!(provenance["links"][0]["provider"], "google");

    let mut changed = ada.clone();
    changed.etag = Some("e2".into());
    changed.title = Some("Countess".into());
    changed.department = Some("Engines".into());
    source.next(vec![changed.clone()], false);
    assert_eq!(f.sync(&source).await.updated, 1);
    assert_eq!(
        f.column(contact, "title").await.as_deref(),
        Some("CTO"),
        "the edit survives"
    );
    assert_eq!(
        f.column(contact, "department").await.as_deref(),
        Some("Engines"),
        "an unlocked field still follows"
    );

    let lock_path = format!("/api/v1/contacts/contacts/{contact}/sync/locks/title");
    assert_eq!(
        f.call(reqwest::Method::DELETE, &lock_path, None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(reqwest::Method::DELETE, &lock_path, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.call(
            reqwest::Method::DELETE,
            &format!("/api/v1/contacts/contacts/{contact}/sync/locks/notes"),
            None
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a field the sync never writes cannot be a lock"
    );
    changed.etag = Some("e3".into());
    source.next(vec![changed], false);
    f.sync(&source).await;
    assert_eq!(
        f.column(contact, "title").await.as_deref(),
        Some("Countess"),
        "released, the source writes it again"
    );

    assert_eq!(
        f.count("SELECT count(*) FROM audit_log WHERE new_values->>'event' IN ('contact_sync.fields_locked', 'contact_sync.lock_released')").await,
        2
    );
}

/// A contact that is not synced is never locked: nothing is protecting it
/// from anything.
#[sqlx::test]
async fn an_edit_to_a_local_contact_locks_nothing(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let contact = Uuid::new_v4();
    sqlx::query("INSERT INTO contacts (id, tenant_id, first_name, last_name) VALUES ($1, $2, 'Local', 'Only')")
        .bind(contact)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&f.pool)
        .await
        .unwrap();
    let (status, _) = f
        .call(
            reqwest::Method::PUT,
            &format!("/api/v1/contacts/contacts/{contact}"),
            Some(json!({ "title": "CTO" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(f.count("SELECT count(*) FROM contact_field_locks").await, 0);
}

/// PSA-70 I: a deletion in Google is visible and changes nothing.
#[sqlx::test]
async fn a_deletion_in_the_source_is_surfaced_and_changes_no_field(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    source.next(
        vec![person("people/g", "e1", "Gone", "gone@acme.example")],
        false,
    );
    f.sync(&source).await;
    let contact = f.linked_contact("people/g").await;

    let mut deleted = person("people/g", "e2", "", "");
    deleted.deleted = true;
    deleted.group_ids.clear();
    source.next(vec![deleted], false);
    assert_eq!(f.sync(&source).await.deleted_in_source, 1);

    let (_, provenance) = f
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/contacts/contacts/{contact}/sync"),
            None,
        )
        .await;
    assert!(
        provenance["links"][0]["deleted_in_source_at"].is_string(),
        "{provenance}"
    );
    let (_, connection) = f
        .call(
            reqwest::Method::GET,
            "/api/v1/integrations/contact-sync",
            None,
        )
        .await;
    assert_eq!(
        connection["connection"]["deleted_in_source"], 1,
        "{connection}"
    );
    assert_eq!(
        f.column(contact, "first_name").await.as_deref(),
        Some("Gone")
    );
    assert_eq!(
        f.column(contact, "email").await.as_deref(),
        Some("gone@acme.example")
    );
}

/// PSA-70 J: disconnecting keeps every contact, as a local record that still
/// says where it came from, and stops locking edits to it.
#[sqlx::test]
async fn a_disconnect_keeps_every_contact_as_a_local_record(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    source.next(
        vec![
            person("people/a", "e1", "Ann", "ann@acme.example"),
            person("people/b", "e1", "Bea", "bea@acme.example"),
        ],
        false,
    );
    assert_eq!(f.sync(&source).await.created, 2);

    let (status, _) = f
        .call(
            reqwest::Method::POST,
            "/api/v1/integrations/contact-sync/google/disconnect",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(
        f.count("SELECT count(*) FROM contacts WHERE email LIKE '%@acme.example'")
            .await,
        2
    );
    let contact = f.linked_contact("people/a").await;
    let (_, provenance) = f
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/contacts/contacts/{contact}/sync"),
            None,
        )
        .await;
    let link = &provenance["links"][0];
    assert_eq!(link["unlink_reason"], "disconnected", "{provenance}");
    assert_eq!(link["provider"], "google");
    assert_eq!(link["source_account_email"], "ops@msp.example");

    let (status, _) = f
        .call(
            reqwest::Method::PUT,
            &format!("/api/v1/contacts/contacts/{contact}"),
            Some(json!({ "title": "CTO" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the edit itself must land");
    assert_eq!(f.count("SELECT count(*) FROM contact_field_locks").await, 0);
    assert_eq!(
        f.count("SELECT count(*) FROM audit_log WHERE new_values->>'event' = 'contact_sync.disconnected' AND (new_values->>'contacts_kept_as_local')::int = 2").await,
        1
    );
}

/// An unlinked contact stays as it is, and the next sync does not link it
/// straight back by its email.
#[sqlx::test]
async fn an_unlinked_contact_is_left_alone_and_not_relinked(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    let ada = person("people/ada", "e1", "Ada", "ada@acme.example");
    source.next(vec![ada.clone()], false);
    f.sync(&source).await;
    let contact = f.linked_contact("people/ada").await;

    let path = format!("/api/v1/contacts/contacts/{contact}/sync/unlink");
    assert_eq!(
        f.call(reqwest::Method::POST, &path, None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call(reqwest::Method::POST, &path, None).await.0,
        StatusCode::NOT_FOUND
    );

    let mut changed = ada;
    changed.etag = Some("e2".into());
    changed.given_name = Some("Augusta".into());
    source.next(vec![changed], true);
    let report = f.sync(&source).await;
    assert_eq!(report.excluded, 1, "{report:?}");
    assert!(!report.changed_anything(), "{report:?}");
    assert_eq!(
        f.column(contact, "first_name").await.as_deref(),
        Some("Ada")
    );
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_links WHERE unlinked_at IS NULL")
            .await,
        0
    );
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 1);
    assert_eq!(
        f.count(
            "SELECT count(*) FROM audit_log WHERE new_values->>'event' = 'contact_sync.unlinked'"
        )
        .await,
        1
    );
}

/// PSA-70 K, the imported case: the contact goes, nothing of the person is
/// kept in the removal's own audit row, and no later sync - not even on a
/// reconnected account - imports them back.
#[sqlx::test]
async fn removing_a_created_contact_deletes_it_and_it_never_comes_back(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    let nora = person("people/nora", "e1", "Nora", "nora@private.example");
    source.next(vec![nora.clone()], false);
    f.sync(&source).await;
    let contact = f.linked_contact("people/nora").await;

    let (status, body) = f
        .call(
            reqwest::Method::POST,
            &format!("/api/v1/contacts/contacts/{contact}/sync/remove-imported-data"),
            Some(json!({ "reason": "Erasure request by email, 2026-09-16" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "contact_deleted": true, "links_removed": 1 }));
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM contact_sync_links").await, 0);
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_suppressions")
            .await,
        1
    );
    let removal: String = sqlx::query_scalar(
        "SELECT new_values::text FROM audit_log WHERE new_values->>'event' = 'contact_sync.imported_data_removed'",
    )
    .fetch_one(&f.pool)
    .await
    .expect("the removal's own audit row");
    assert!(
        !removal.contains("nora"),
        "the removal's audit row must not keep the person: {removal}"
    );
    assert!(removal.contains("Erasure request"), "{removal}");

    source.next(vec![nora.clone()], true);
    assert_eq!(f.sync(&source).await.excluded, 1);

    // Disconnect, reconnect the same account, sync again: still gone.
    sqlx::query("UPDATE contact_sync_connections SET disconnected_at = NOW(), is_active = FALSE")
        .execute(&f.pool)
        .await
        .unwrap();
    let reconnected = seed_connection(&f.pool).await;
    source.next(vec![nora], false);
    let report = f.sync_connection(reconnected, &source).await;
    assert_eq!((report.excluded, report.created), (1, 0));
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 0);
}

/// PSA-70 K, the linked case: a contact the CRM already held keeps its record
/// and loses only what the import attached.
#[sqlx::test]
async fn removing_a_linked_contact_keeps_the_crm_record(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let existing = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, first_name, last_name, email) \
         VALUES ($1, $2, 'Ada', 'Lovelace', 'ada@acme.example')",
    )
    .bind(existing)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&f.pool)
    .await
    .unwrap();
    let source = FakeSource::new();
    source.next(
        vec![person("people/ada", "e1", "Ada", "ada@acme.example")],
        false,
    );
    assert_eq!(f.sync(&source).await.linked, 1);

    let (status, body) = f
        .call(
            reqwest::Method::POST,
            &format!("/api/v1/contacts/contacts/{existing}/sync/remove-imported-data"),
            Some(json!({ "reason": "requested" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["contact_deleted"], false);
    assert_eq!(
        f.column(existing, "email").await.as_deref(),
        Some("ada@acme.example")
    );
    let (_, provenance) = f
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/contacts/contacts/{existing}/sync"),
            None,
        )
        .await;
    assert_eq!(provenance["links"], json!([]));
}

/// A contact tickets refer to cannot be deleted, and then nothing at all is
/// removed: not the link, not the marker.
#[sqlx::test]
async fn a_removal_the_database_refuses_removes_nothing(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    source.next(
        vec![person("people/t", "e1", "Tess", "tess@acme.example")],
        false,
    );
    f.sync(&source).await;
    let contact = f.linked_contact("people/t").await;
    let company = common::seed_company(&f.pool).await;
    let (ticket, _) = common::seed_ticket_and_note(&f.pool, f.admin_id, company).await;
    sqlx::query("UPDATE tickets SET contact_id = $1 WHERE id = $2")
        .bind(contact)
        .bind(ticket)
        .execute(&f.pool)
        .await
        .unwrap();

    let (status, body) = f
        .call(
            reqwest::Method::POST,
            &format!("/api/v1/contacts/contacts/{contact}/sync/remove-imported-data"),
            Some(json!({ "reason": "requested" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("Nothing was removed"), "{body}");
    assert_eq!(f.count("SELECT count(*) FROM contact_sync_links").await, 1);
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_suppressions")
            .await,
        0
    );
}

/// Removal deletes a person: an admin's act, with a stated reason.
#[sqlx::test]
async fn only_an_admin_removes_imported_data_and_says_why(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    source.next(
        vec![person("people/r", "e1", "Rae", "rae@acme.example")],
        false,
    );
    f.sync(&source).await;
    let contact = f.linked_contact("people/r").await;
    let path = format!("/api/v1/contacts/contacts/{contact}/sync/remove-imported-data");

    let (_id, email, password) = common::seed_user(
        &f.pool,
        common::DEFAULT_TENANT_ID,
        "tech@contact-sync.example",
        "technician",
    )
    .await;
    let tech = common::login(&f.app, &email, &password).await;
    let (status, _) = f
        .call_as(
            &tech,
            reqwest::Method::POST,
            &path,
            Some(json!({ "reason": "requested" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = f
        .call(
            reqwest::Method::POST,
            &path,
            Some(json!({ "reason": "   " })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 1);
}

/// PMS-1260: the list says where each contact came from in the same page
/// read, and filters by it. An unlinked contact still came from Google.
#[sqlx::test]
async fn the_list_says_where_a_contact_came_from_and_filters_by_it(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let source = FakeSource::new();
    source.next(
        vec![person(
            "people/i",
            "e1",
            "Imported",
            "imported@acme.example",
        )],
        false,
    );
    f.sync(&source).await;
    let imported = f.linked_contact("people/i").await;
    let manual = Uuid::new_v4();
    sqlx::query("INSERT INTO contacts (id, tenant_id, first_name, last_name) VALUES ($1, $2, 'Hand', 'Entered')")
        .bind(manual)
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&f.pool)
        .await
        .unwrap();

    let f = &f;
    let list = |query: &'static str| async move {
        let path = format!("/api/v1/contacts/contacts{query}");
        f.call(reqwest::Method::GET, &path, None).await
    };
    let ids = |body: &Value| -> Vec<String> {
        body["data"]
            .as_array()
            .expect("a page")
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_string())
            .collect()
    };

    let (status, all) = list("").await;
    assert_eq!(status, StatusCode::OK, "{all}");
    let row = |id: Uuid| {
        all["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == json!(id))
            .cloned()
            .expect("listed")
    };
    assert_eq!(
        row(imported)["imported_from"],
        json!({
            "provider": "google",
            "account_email": "ops@msp.example",
            "linked": true,
            "deleted_in_source": false,
        })
    );
    assert!(row(manual)["imported_from"].is_null());

    let (_, google) = list("?origin=google").await;
    assert_eq!(ids(&google), vec![imported.to_string()]);
    let (_, hand) = list("?origin=manual").await;
    assert!(ids(&hand).contains(&manual.to_string()));
    assert!(!ids(&hand).contains(&imported.to_string()));
    assert_eq!(list("?origin=elsewhere").await.0, StatusCode::BAD_REQUEST);

    f.call(
        reqwest::Method::POST,
        &format!("/api/v1/contacts/contacts/{imported}/sync/unlink"),
        None,
    )
    .await;
    let (_, after) = list("?origin=google").await;
    assert_eq!(
        ids(&after),
        vec![imported.to_string()],
        "unlinked, still imported"
    );
    assert_eq!(after["data"][0]["imported_from"]["linked"], false);
}
