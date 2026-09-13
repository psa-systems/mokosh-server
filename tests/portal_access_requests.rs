//! PMS-1187: a portal contact can ask for access, and the MSP is told.
//!
//! A contact who lacks a capability meets an empty screen and has no way to
//! say so; the MSP hears nothing either way, because nothing records that a
//! customer tried to reach something and could not. PMS-1186 closes the one
//! case where the MSP had already designated a billing contact; this is the
//! path for every other one.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn role_ids_for(pool: &PgPool, names: &[&str]) -> Vec<Uuid> {
    let mut ids = Vec::new();
    for name in names {
        let id: Uuid =
            sqlx::query_scalar("SELECT id FROM portal_roles WHERE tenant_id = $1 AND name = $2")
                .bind(common::DEFAULT_TENANT_ID)
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("read portal_role {name}: {e}"));
        ids.push(id);
    }
    ids
}

/// A portal contact holding `roles`, signed in, with their contact id and a
/// contact-plane access token.
async fn seed_portal_contact(
    app: &common::TestApp,
    pool: &PgPool,
    label: &str,
    roles: &[&str],
) -> (Uuid, String) {
    let company_id = Uuid::new_v4();
    let slug = format!("par-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO companies (id, tenant_id, name, portal_slug) VALUES ($1, $2, $3, $4)")
        .bind(company_id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(format!("Access Request Co {label}"))
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed company");

    let contact_id = Uuid::new_v4();
    let email = format!("{label}@access-requests.example");
    sqlx::query(
        "INSERT INTO contacts (id, tenant_id, company_id, first_name, last_name, email) \
         VALUES ($1, $2, $3, 'Ada', 'Asker', $4)",
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(&email)
    .execute(pool)
    .await
    .expect("seed contact");

    let db = mokosh_server::Database::from_pool(pool.clone());
    let contact_svc = mokosh_server::modules::contacts::ContactService::new(db);
    let outcome = contact_svc
        .grant_portal_access(
            mokosh_server::modules::auth::TenantId::from_trusted(common::DEFAULT_TENANT_ID),
            contact_id,
            &role_ids_for(pool, roles).await,
            &mokosh_server::modules::audit::AuditCtx::system(common::DEFAULT_TENANT_ID),
        )
        .await
        .expect("grant_portal_access");

    let prefix = format!("/portal/{}/set-password?token=", outcome.portal_slug);
    let setup_token = outcome
        .setup_link
        .split(&prefix)
        .nth(1)
        .expect("setup token in the link")
        .to_string();
    let password = "Portal-Access-1!";
    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/set-password"))
        .json(&serde_json::json!({ "token": setup_token, "password": password }))
        .send()
        .await
        .expect("set password");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "set the password");

    let resp = app
        .client
        .post(app.url("/api/v1/contact/auth/login"))
        .json(&serde_json::json!({
            "portal_id": outcome.portal_id,
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("login");
    assert_eq!(resp.status(), StatusCode::OK, "sign the contact in");
    let body: Value = resp.json().await.expect("json");
    let token = body["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    (contact_id, token)
}

async fn ask_for(
    app: &common::TestApp,
    token: &str,
    area: &str,
    note: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = serde_json::json!({ "area": area });
    if let Some(note) = note {
        body["note"] = Value::String(note.to_string());
    }
    let resp = app
        .client
        .post(app.url("/api/v1/contact/access-requests"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("request access");
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn open_requests(pool: &PgPool, contact_id: Uuid) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT area, status, note FROM portal_access_requests \
         WHERE tenant_id = $1 AND contact_id = $2 ORDER BY requested_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .fetch_all(pool)
    .await
    .expect("read requests")
}

/// The case this exists for: a contact whose access was set up for tickets
/// meets an empty Invoices screen and can say so.
#[sqlx::test]
async fn a_contact_can_ask_for_an_area_they_cannot_reach(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (contact_id, token) = seed_portal_contact(&app, &pool, "asks", &["Support Contact"]).await;

    let (status, body) = ask_for(&app, &token, "invoices", Some("I pay these")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["area"], "invoices");
    assert_eq!(body["status"], "open");

    let rows = open_requests(&pool, contact_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "invoices");
    assert_eq!(rows[0].1, "open");
    assert_eq!(rows[0].2.as_deref(), Some("I pay these"));
}

/// Pressing the button twice answers the first request rather than opening a
/// second one, which is also what stops this being a way to generate mail.
#[sqlx::test]
async fn asking_twice_is_one_request(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (contact_id, token) = seed_portal_contact(&app, &pool, "twice", &["Support Contact"]).await;

    let (first_status, first) = ask_for(&app, &token, "invoices", Some("first")).await;
    let (second_status, second) = ask_for(&app, &token, "invoices", Some("second")).await;
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(first["id"], second["id"], "the same request comes back");

    let rows = open_requests(&pool, contact_id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].2.as_deref(),
        Some("first"),
        "the first note stands; the second press is not an edit"
    );
}

/// Asking for what you already hold produces a task with nothing to do, so it
/// is refused and says why.
#[sqlx::test]
async fn asking_for_an_area_you_can_already_reach_is_refused(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (contact_id, token) = seed_portal_contact(&app, &pool, "holder", &["Read-Only"]).await;

    let (status, body) = ask_for(&app, &token, "invoices", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("already"),
        "the refusal has to say why: {body}"
    );
    assert!(open_requests(&pool, contact_id).await.is_empty());
}

/// An area outside the closed set is a client bug, refused rather than stored:
/// the column must never hold free text an MSP has to interpret.
#[sqlx::test]
async fn an_unknown_area_is_refused(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let (contact_id, token) =
        seed_portal_contact(&app, &pool, "unknown", &["Support Contact"]).await;

    let (status, _body) = ask_for(&app, &token, "payroll", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(open_requests(&pool, contact_id).await.is_empty());
}

/// Granting assigns the area's built-in role and closes the request in one
/// action, which is the point: the step most likely to be skipped is the one
/// that makes anything happen for the customer.
#[sqlx::test]
async fn granting_a_request_assigns_the_role_and_closes_it(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let (contact_id, token) =
        seed_portal_contact(&app, &pool, "granted", &["Support Contact"]).await;
    let (_status, request) = ask_for(&app, &token, "invoices", None).await;
    let request_id = request["id"].as_str().expect("request id");

    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/contacts/contacts/{contact_id}/access-requests"
        )))
        .bearer_auth(&staff_token)
        .send()
        .await
        .expect("list requests");
    assert_eq!(resp.status(), StatusCode::OK);
    let listed: Value = resp.json().await.expect("json");
    assert_eq!(listed[0]["area"], "invoices");

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/contacts/access-requests/{request_id}/resolve"
        )))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({ "grant": true }))
        .send()
        .await
        .expect("resolve");
    assert_eq!(resp.status(), StatusCode::OK);
    let resolved: Value = resp.json().await.expect("json");
    assert_eq!(resolved["status"], "granted");

    let caps: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT cap FROM contact_role_assignments cra \
         INNER JOIN portal_roles pr ON pr.id = cra.role_id, \
         LATERAL unnest(pr.capabilities) AS cap \
         WHERE cra.tenant_id = $1 AND cra.contact_id = $2",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(contact_id)
    .fetch_all(&pool)
    .await
    .expect("read caps");
    assert!(
        caps.contains(&"invoices:read".to_string()),
        "granting has to actually grant: {caps:?}"
    );
}

/// Declining closes the request without granting, and records that somebody
/// answered rather than leaving it to rot.
#[sqlx::test]
async fn declining_closes_the_request_without_granting(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let (contact_id, token) =
        seed_portal_contact(&app, &pool, "declined", &["Support Contact"]).await;
    let (_status, request) = ask_for(&app, &token, "invoices", None).await;
    let request_id = request["id"].as_str().expect("request id");

    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/contacts/contacts/access-requests/{request_id}/resolve"
        )))
        .bearer_auth(&staff_token)
        .json(&serde_json::json!({ "grant": false }))
        .send()
        .await
        .expect("resolve");
    assert_eq!(resp.status(), StatusCode::OK);

    let rows = open_requests(&pool, contact_id).await;
    assert_eq!(rows[0].1, "declined");
    let resolved_by: Option<Uuid> = sqlx::query_scalar(
        "SELECT resolved_by_id FROM portal_access_requests WHERE contact_id = $1",
    )
    .bind(contact_id)
    .fetch_one(&pool)
    .await
    .expect("read resolver");
    assert!(resolved_by.is_some(), "who answered it is recorded");
}

/// A request that was already answered cannot be answered again.
#[sqlx::test]
async fn a_resolved_request_cannot_be_resolved_twice(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let staff_token = common::login(&app, &email, &password).await;
    let (_contact_id, token) =
        seed_portal_contact(&app, &pool, "twiceres", &["Support Contact"]).await;
    let (_status, request) = ask_for(&app, &token, "invoices", None).await;
    let request_id = request["id"].as_str().expect("request id");
    let url = app.url(&format!(
        "/api/v1/contacts/contacts/access-requests/{request_id}/resolve"
    ));

    for expected in [StatusCode::OK, StatusCode::CONFLICT] {
        let resp = app
            .client
            .post(&url)
            .bearer_auth(&staff_token)
            .json(&serde_json::json!({ "grant": true }))
            .send()
            .await
            .expect("resolve");
        assert_eq!(resp.status(), expected);
    }
}
