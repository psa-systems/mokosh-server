//! PMS-1290 (PSA-70, vCard addendum): an uploaded `.vcf` file imports through
//! the same preview, review queue and run as Google Contacts.
//!
//! Everything here is the real code: the multipart route, the reader, local
//! storage under the suite's own root, the engine, the runner and the review
//! routes, against the RLS-bound app role. The runner's Google factory is
//! never reached by a file run, and says so if it is.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use mokosh_server::db::Database;
use mokosh_server::modules::auth::TenantId;
use mokosh_server::modules::contact_sync::provider::ContactSyncProvider;
use mokosh_server::modules::contact_sync::runs::{ContactSyncRunner, SourceFactory};
use mokosh_server::utils::error::AppResult;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const UNGROUPED: &str = "mokosh:ungrouped";

/// A file run must never ask for a Google credential.
struct NoGoogle;

#[async_trait]
impl SourceFactory for NoGoogle {
    async fn source(
        &self,
        _tenant_id: TenantId,
        _connection_id: Uuid,
        provider: &str,
    ) -> AppResult<Box<dyn ContactSyncProvider>> {
        panic!("a {provider} source was requested from the Google factory");
    }
}

struct Fixture {
    app: common::TestApp,
    pool: PgPool,
    runner: ContactSyncRunner,
    admin: String,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        common::storage_root();
        let (_admin_id, email, password) = common::seed_admin(&pool).await;
        let app_pool = common::build_app_role_pool(&pool).await;
        let runner = ContactSyncRunner::new(
            Database::from_pools(app_pool, pool.clone()),
            Arc::new(NoGoogle),
            None,
            "https://app.msp.example".into(),
        );
        let app = common::boot_rls(pool.clone()).await;
        let admin = common::login(&app, &email, &password).await;
        Self {
            app,
            pool,
            runner,
            admin,
        }
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut request = self
            .app
            .client
            .request(method, self.app.url(path))
            .bearer_auth(&self.admin);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("request");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn upload_as(&self, token: &str, name: &str, bytes: Vec<u8>) -> (StatusCode, Value) {
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(name.to_string())
            .mime_str("text/vcard")
            .expect("mime");
        let response = self
            .app
            .client
            .post(
                self.app
                    .url("/api/v1/integrations/contact-sync/vcard/uploads"),
            )
            .bearer_auth(token)
            .multipart(reqwest::multipart::Form::new().part("file", part))
            .send()
            .await
            .expect("upload");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn upload(&self, name: &str, text: &str) -> Value {
        let (status, body) = self
            .upload_as(&self.admin, name, text.as_bytes().to_vec())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body
    }

    /// Import the chosen groups and run the import now.
    async fn import(&self, uploaded: &Value, groups: &[&str]) -> Value {
        let file_id = uploaded["file"]["id"].as_str().expect("file id");
        let (status, run) = self
            .call(
                Method::POST,
                &format!("/api/v1/integrations/contact-sync/vcard/uploads/{file_id}/import"),
                Some(json!({ "group_ids": groups })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{run}");
        let run_id: Uuid = run["id"].as_str().unwrap().parse().unwrap();
        self.runner
            .execute_run(TenantId::from_trusted(common::DEFAULT_TENANT_ID), run_id)
            .await
            .expect("execute run");
        let (status, run) = self
            .call(
                Method::GET,
                &format!("/api/v1/integrations/contact-sync/runs/{run_id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        run
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    async fn contact_by_email(&self, email: &str) -> Uuid {
        sqlx::query_scalar("SELECT id FROM contacts WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("contact {email}: {e}"))
    }
}

fn card(body: &str) -> String {
    format!("BEGIN:VCARD\r\nVERSION:3.0\r\n{body}END:VCARD\r\n")
}

fn book() -> String {
    [
        card("N:Lovelace;Ada;;;\r\nFN:Ada Lovelace\r\nEMAIL;TYPE=work:ada@engines.example\r\nORG:Engines Ltd;Research\r\nNOTE:Prefers email.\\nCall after 3pm.\r\nCATEGORIES:Client\r\nUID:ada-1\r\n"),
        card("FN:Grace Hopper\r\nEMAIL:grace@navy.example\r\nCATEGORIES:Client,VIP\r\n"),
        card("FN:Linus Friend\r\nEMAIL:linus@friends.example\r\nCATEGORIES:Personal\r\n"),
    ]
    .concat()
}

/// The whole path: upload previews without writing a contact, import writes
/// them with the file as their provenance, and the held upload is discarded
/// when the run ends.
#[sqlx::test]
async fn an_uploaded_file_previews_imports_and_is_then_discarded(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let uploaded = f.upload("Office contacts.vcf", &book()).await;
    assert_eq!(uploaded["file"]["filename"], "Office contacts.vcf");
    assert_eq!(uploaded["file"]["contacts"], 3);
    let groups: Vec<&str> = uploaded["preview"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["id"].as_str().unwrap())
        .collect();
    assert_eq!(groups, vec!["Client", "Personal", "VIP"]);
    assert_eq!(uploaded["preview"]["totals"]["create"], 3);
    assert_eq!(
        f.count("SELECT count(*) FROM contacts").await,
        0,
        "a preview writes no contact"
    );

    let run = f.import(&uploaded, &["Client"]).await;
    assert_eq!(run["status"], "completed", "{run}");
    assert_eq!(run["created"], 2);
    assert_eq!(run["full_read"], false, "a file is never a full read");

    let ada = f.contact_by_email("ada@engines.example").await;
    let (_, contact) = f
        .call(
            Method::GET,
            &format!("/api/v1/contacts/contacts/{ada}"),
            None,
        )
        .await;
    assert_eq!(contact["notes"], "Prefers email.\nCall after 3pm.");
    assert_eq!(contact["department"], "Research");
    assert_eq!(contact["tags"], json!(["Client"]));
    assert_eq!(contact["imported_from"]["provider"], "vcard");
    assert_eq!(
        contact["imported_from"]["account_email"],
        "Office contacts.vcf"
    );
    assert_eq!(
        f.count("SELECT count(*) FROM contacts WHERE email = 'linus@friends.example'")
            .await,
        0,
        "an unselected category is not imported"
    );

    let (_, provenance) = f
        .call(
            Method::GET,
            &format!("/api/v1/contacts/contacts/{ada}/sync"),
            None,
        )
        .await;
    let link = &provenance["links"][0];
    assert_eq!(link["provider"], "vcard");
    assert_eq!(link["external_id"], "ada-1", "the UID is the identity");
    assert_eq!(link["import_file_name"], "Office contacts.vcf");
    assert_eq!(link["import_file_uploaded_by_name"], "Test Admin");
    assert!(link["import_file_uploaded_at"].is_string());

    let file_id: Uuid = uploaded["file"]["id"].as_str().unwrap().parse().unwrap();
    let object = common::storage_root()
        .join(common::DEFAULT_TENANT_ID.to_string())
        .join("contact-imports")
        .join(file_id.to_string());
    assert!(!object.exists(), "the upload is discarded after its run");
    let (_, file) = f
        .call(
            Method::GET,
            &format!("/api/v1/integrations/contact-sync/vcard/uploads/{file_id}"),
            None,
        )
        .await;
    assert!(file["discarded_at"].is_string(), "{file}");
    assert_eq!(file["latest_run"]["status"], "completed");

    // The Google card still reads "not connected": the file's source row is
    // not the Google connection.
    let (_, overview) = f
        .call(Method::GET, "/api/v1/integrations/contact-sync", None)
        .await;
    assert_eq!(overview["connection"], Value::Null, "{overview}");
}

/// Importing the same file twice creates nothing the second time, including
/// the cards with no UID, which is what the content digest is for.
#[sqlx::test]
async fn the_same_file_twice_creates_nothing_the_second_time(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let first = f.upload("book.vcf", &book()).await;
    assert_eq!(
        f.import(&first, &["Client", "Personal"]).await["created"],
        3
    );

    let again = f.upload("book (1).vcf", &book()).await;
    assert_eq!(again["preview"]["totals"]["create"], 0, "{again}");
    assert_eq!(again["preview"]["totals"]["imported"], 3);
    let run = f.import(&again, &["Client", "Personal"]).await;
    assert_eq!(run["created"], 0, "{run}");
    assert_eq!(run["linked"], 0);
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 3);
}

/// A later file that leaves someone out is not a deletion: a file is
/// whatever somebody exported, never the whole address book.
#[sqlx::test]
async fn a_contact_missing_from_a_later_file_is_not_flagged_deleted(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let first = f.upload("all.vcf", &book()).await;
    f.import(&first, &["Client", "Personal"]).await;

    let fewer = f
        .upload(
            "one.vcf",
            &card("FN:Grace Hopper\r\nEMAIL:grace@navy.example\r\nCATEGORIES:Client\r\n"),
        )
        .await;
    let run = f.import(&fewer, &["Client"]).await;
    assert_eq!(run["deleted_in_source"], 0, "{run}");
    assert_eq!(
        f.count("SELECT count(*) FROM contact_sync_links WHERE deleted_in_source_at IS NOT NULL")
            .await,
        0
    );
}

/// A file with no CATEGORIES at all is imported through "No category", which
/// never becomes a tag.
#[sqlx::test]
async fn a_file_without_categories_imports_through_no_category(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let uploaded = f
        .upload(
            "phone.vcf",
            &[
                card("FN:Prince\r\n"),
                card("N:Lovelace;Ada;;;\r\nEMAIL:ada@x.example\r\n"),
            ]
            .concat(),
        )
        .await;
    assert_eq!(
        uploaded["preview"]["groups"],
        json!([{ "id": UNGROUPED, "name": "No category", "member_count": 2 }])
    );
    let run = f.import(&uploaded, &[UNGROUPED]).await;
    assert_eq!(run["created"], 2, "{run}");
    assert_eq!(
        f.count("SELECT count(*) FROM contacts WHERE tags <> '{}'")
            .await,
        0,
        "No category is not a tag"
    );
}

/// One malformed card costs only itself, and is reported where the admin
/// looks before importing.
#[sqlx::test]
async fn a_malformed_card_is_reported_and_the_rest_imports(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let text = [
        card("FN:First\r\nEMAIL:first@x.example\r\n"),
        "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Broken\r\n".to_string(),
        card("FN:Last\r\nEMAIL:last@x.example\r\n"),
    ]
    .concat();
    let uploaded = f.upload("messy.vcf", &text).await;
    let failures = uploaded["file"]["failures"].as_array().expect("failures");
    assert_eq!(failures.len(), 1, "{uploaded}");
    assert_eq!(failures[0]["card"], 2);
    assert_eq!(failures[0]["hint"], "FN:Broken");
    assert_eq!(uploaded["file"]["contacts"], 2);
    assert_eq!(f.import(&uploaded, &[UNGROUPED]).await["created"], 2);
}

/// The same person in Google and in a file is one Mokosh contact with two
/// links, matched by email.
#[sqlx::test]
async fn a_person_in_google_and_in_a_file_is_one_contact(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (status, contact) = f
        .call(
            Method::POST,
            "/api/v1/contacts/contacts",
            Some(json!({ "first_name": "Grace", "last_name": "Hopper", "email": "grace@navy.example" })),
        )
        .await;
    assert!(status.is_success(), "{status}: {contact}");
    let grace: Uuid = contact["id"].as_str().unwrap().parse().unwrap();
    let google = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contact_sync_connections (id, tenant_id, provider, account_email, selected_groups) \
         VALUES ($1, $2, 'google', 'ops@msp.example', '[\"contactGroups/clients\"]')",
    )
    .bind(google)
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&f.pool)
    .await
    .expect("google connection");
    sqlx::query(
        "INSERT INTO contact_sync_links (tenant_id, connection_id, provider, source_account_email, external_id, contact_id, origin) \
         VALUES ($1, $2, 'google', 'ops@msp.example', 'people/c9', $3, 'created')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(google)
    .bind(grace)
    .execute(&f.pool)
    .await
    .expect("google link");

    let uploaded = f
        .upload(
            "grace.vcf",
            &card("FN:Grace Hopper\r\nEMAIL:GRACE@navy.example\r\nCATEGORIES:Client\r\n"),
        )
        .await;
    let run = f.import(&uploaded, &["Client"]).await;
    assert_eq!(
        (run["created"].clone(), run["linked"].clone()),
        (json!(0), json!(1)),
        "{run}"
    );
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 1);
    let providers: Vec<String> = sqlx::query_scalar(
        "SELECT provider FROM contact_sync_links WHERE contact_id = $1 ORDER BY provider",
    )
    .bind(grace)
    .fetch_all(&f.pool)
    .await
    .unwrap();
    assert_eq!(providers, vec!["google", "vcard"]);
}

/// A card that matches only by phone goes to the one review queue, says which
/// file proposed it, and an answer links it with the file as provenance.
#[sqlx::test]
async fn a_phone_match_is_reviewed_in_the_shared_queue(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (status, contact) = f
        .call(
            Method::POST,
            "/api/v1/contacts/contacts",
            Some(json!({
                "first_name": "Margaret", "last_name": "Hamilton",
                "email": format!("margaret-{}@example.com", Uuid::new_v4()),
                "phones": [{ "phone_type": "mobile", "number": "+14155550100", "is_primary": true }]
            })),
        )
        .await;
    assert!(status.is_success(), "{status}: {contact}");
    let margaret: Uuid = contact["id"].as_str().unwrap().parse().unwrap();

    let uploaded = f
        .upload(
            "apollo.vcf",
            &card("FN:M. Hamilton\r\nTEL;TYPE=cell:+1 415 555 0100\r\nUID:mh-1\r\n"),
        )
        .await;
    let run = f.import(&uploaded, &[UNGROUPED]).await;
    assert_eq!(run["queued_for_review"], 1, "{run}");

    let (status, queue) = f
        .call(
            Method::GET,
            "/api/v1/integrations/contact-sync/review-queue",
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a tenant with no Google connection has a queue"
    );
    assert_eq!(queue[0]["provider"], "vcard");
    assert_eq!(queue[0]["source_label"], "apollo.vcf");
    assert_eq!(queue[0]["external_id"], "mh-1");

    let (status, resolved) = f
        .call(
            Method::POST,
            "/api/v1/integrations/contact-sync/review-queue/resolve",
            Some(json!({ "action": "link", "external_id": "mh-1", "contact_id": margaret })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    let (_, provenance) = f
        .call(
            Method::GET,
            &format!("/api/v1/contacts/contacts/{margaret}/sync"),
            None,
        )
        .await;
    assert_eq!(provenance["links"][0]["import_file_name"], "apollo.vcf");
    assert_eq!(provenance["links"][0]["source_account_email"], "apollo.vcf");
}

/// A PHOTO that names an address is kept as text and never requested: a
/// listener named in the card sees no connection through upload, preview and
/// import.
#[sqlx::test]
async fn a_remote_photo_is_never_requested(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().unwrap();
    let uploaded = f
        .upload(
            "linked.vcf",
            &card(&format!(
                "FN:Linked Photo\r\nEMAIL:photo@x.example\r\nPHOTO;VALUE=uri:http://{address}/p.jpg\r\n"
            )),
        )
        .await;
    assert_eq!(f.import(&uploaded, &[UNGROUPED]).await["created"], 1);
    let accepted =
        tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept()).await;
    assert!(accepted.is_err(), "something connected to {address}");
}

/// An oversized file is refused whole with the shared 413 and stores nothing.
#[sqlx::test]
async fn an_oversized_file_is_refused_cleanly(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let mut bytes = card("FN:A\r\n").into_bytes();
    bytes.resize(10 * 1024 * 1024 + 1, b'\n');
    let (status, body) = f.upload_as(&f.admin, "huge.vcf", bytes).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert!(body.to_string().contains("vCard file exceeds"), "{body}");
    assert_eq!(
        f.count("SELECT count(*) FROM contact_import_files").await,
        0
    );
}

/// A file that is not a vCard, an empty choice, a category the file does not
/// have, and a non-admin are each refused with something to act on.
#[sqlx::test]
async fn bad_uploads_and_choices_are_refused(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (status, body) = f
        .upload_as(&f.admin, "notes.txt", b"just some text".to_vec())
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.to_string().contains("BEGIN:VCARD"), "{body}");

    let uploaded = f.upload("book.vcf", &book()).await;
    let file_id = uploaded["file"]["id"].as_str().unwrap();
    let path = format!("/api/v1/integrations/contact-sync/vcard/uploads/{file_id}/import");
    for groups in [json!([]), json!(["Nope"])] {
        let (status, body) = f
            .call(Method::POST, &path, Some(json!({ "group_ids": groups })))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{groups}: {body}");
    }

    let (_, email, password) = common::seed_user(
        &f.pool,
        common::DEFAULT_TENANT_ID,
        "tech@msp.example",
        "technician",
    )
    .await;
    let tech = common::login(&f.app, &email, &password).await;
    let (status, _) = f.upload_as(&tech, "book.vcf", book().into_bytes()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// An upload nobody imports is discarded after its hold, by the runner's tick.
#[sqlx::test]
async fn an_abandoned_upload_is_discarded_after_its_hold(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let uploaded = f.upload("left.vcf", &book()).await;
    let file_id: Uuid = uploaded["file"]["id"].as_str().unwrap().parse().unwrap();
    let object = common::storage_root()
        .join(common::DEFAULT_TENANT_ID.to_string())
        .join("contact-imports")
        .join(file_id.to_string());
    assert!(object.exists(), "held until imported or expired");

    sqlx::query(
        "UPDATE contact_import_files SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(file_id)
    .execute(&f.pool)
    .await
    .unwrap();
    f.runner.tick().await.expect("tick");
    assert!(!object.exists());
    let (status, body) = f
        .call(
            Method::POST,
            &format!("/api/v1/integrations/contact-sync/vcard/uploads/{file_id}/import"),
            Some(json!({ "group_ids": ["Client"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("no longer held"), "{body}");
}
