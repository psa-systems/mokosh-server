//! PMS-1084: a contact decides the approvals addressed to it, on the
//! same `GET /approvals/pending` and `POST /approvals/{id}/decision`
//! the staff SPA calls. A staff user addresses an approval to a
//! contact with `approver_contact_id`; the contact, holding
//! `approvals:decide`, lists only those rows and decides each once;
//! a sibling's row, a staff row and an unknown id are 404 alike.

mod common;

use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_company(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_ticket(pool: &PgPool, company: Uuid, admin_id: Uuid, title: &str) -> Uuid {
    let status_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_statuses WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("status");
    let priority_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_priorities WHERE tenant_id = $1 ORDER BY sort_order LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("priority");
    let queue_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM ticket_queues WHERE tenant_id = $1 ORDER BY name LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("queue");
    let ticket_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id, \
                              queue_id, company_id, created_by_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(ticket_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &ticket_id.to_string()[..8]))
    .bind(title)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    ticket_id
}

/// Address an approval on `ticket` to `contact` through the staff API.
async fn address_to_contact(
    app: &common::TestApp,
    staff: &str,
    ticket: Uuid,
    contact: Uuid,
    notes: &str,
) -> Value {
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket}/approvals")))
        .bearer_auth(staff)
        .json(&json!({ "approver_contact_id": contact, "notes": notes }))
        .send()
        .await
        .expect("create approval");
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str(&text).unwrap()
}

async fn pending(app: &common::TestApp, token: &str) -> (StatusCode, Value) {
    let resp = app
        .client
        .get(app.url("/api/v1/approvals/pending"))
        .bearer_auth(token)
        .send()
        .await
        .expect("pending");
    let status = resp.status();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn decide(app: &common::TestApp, token: &str, id: Uuid, decision: &str) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/approvals/{id}/decision")))
        .bearer_auth(token)
        .json(&json!({ "decision": decision, "decision_notes": "noted" }))
        .send()
        .await
        .expect("decide")
}

fn ids(body: &Value) -> Vec<String> {
    let mut v: Vec<String> = body
        .as_array()
        .expect("array")
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    v.sort();
    v
}

// A staff user addresses two approvals to a contact; the contact lists
// exactly those, decides one each way, and cannot decide twice. The
// decision records the contact and writes the audit row.
#[sqlx::test]
async fn a_contact_lists_and_decides_the_approvals_addressed_to_it(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Approvals Co").await;
    let me =
        common::seed_portal_contact(&pool, company, "me@example.com", &["Support Contact"]).await;
    let sibling =
        common::seed_portal_contact(&pool, company, "sib@example.com", &["Support Contact"]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;
    let t1 = seed_ticket(&pool, company, admin_id, "Server down").await;
    let t2 = seed_ticket(&pool, company, admin_id, "Replace switch").await;
    let t3 = seed_ticket(&pool, company, admin_id, "Sibling's ticket").await;

    let a1 = address_to_contact(&app, &staff, t1, me.id, "Please approve").await;
    let a2 = address_to_contact(&app, &staff, t2, me.id, "Out of scope").await;
    let a3 = address_to_contact(&app, &staff, t3, sibling.id, "Not mine").await;
    assert_eq!(a1["approver_contact_id"], me.id.to_string());
    assert_eq!(a1["approver_contact_name"], "Portal Contact");
    assert!(a1["approver_user_id"].is_null());
    let a1 = Uuid::parse_str(a1["id"].as_str().unwrap()).unwrap();
    let a2 = Uuid::parse_str(a2["id"].as_str().unwrap()).unwrap();
    let a3 = Uuid::parse_str(a3["id"].as_str().unwrap()).unwrap();

    let token = common::contact_token(&app, &me).await;
    let (status, body) = pending(&app, &token).await;
    assert_eq!(status, StatusCode::OK);
    let mut expected = vec![a1.to_string(), a2.to_string()];
    expected.sort();
    assert_eq!(ids(&body), expected);
    assert!(body[0]["entity_label"]
        .as_str()
        .map(|s| s == "Server down" || s == "Replace switch")
        .unwrap_or(false));
    assert_eq!(body[0]["target"], "ticket");

    // Approve one, reject the other; each once.
    let ok = decide(&app, &token, a1, "approve").await;
    assert_eq!(ok.status(), StatusCode::OK);
    let decided: Value = ok.json().await.unwrap();
    assert_eq!(decided["status"], "approved");
    assert_eq!(decided["decided_by_contact_id"], me.id.to_string());
    assert!(decided["decided_by_id"].is_null());
    assert_eq!(decided["decision_notes"], "noted");
    let rejected = decide(&app, &token, a2, "reject").await;
    assert_eq!(rejected.status(), StatusCode::OK);
    let again = decide(&app, &token, a1, "reject").await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST, "decided once");
    let (_, after) = pending(&app, &token).await;
    assert!(after.as_array().unwrap().is_empty());
    let (_, sibling_view) = pending(&app, &common::contact_token(&app, &sibling).await).await;
    assert_eq!(ids(&sibling_view), vec![a3.to_string()]);

    // The staff side sees the outcome and who decided.
    let listed: Value = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{t1}/approvals")))
        .bearer_auth(&staff)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed[0]["status"], "approved");
    assert_eq!(listed[0]["decided_by_contact_name"], "Portal Contact");

    let audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE entity_type = 'portal_contact' \
         AND entity_id = $1 AND new_values ->> 'event' IN ('portal.approval_approved', 'portal.approval_rejected')",
    )
    .bind(me.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audits, 2);
}

// Anything not addressed to the contact is a 404 on decide: a
// sibling's row, a row addressed to a staff user, an unknown id. And
// staff cannot decide a row addressed to a contact.
#[sqlx::test]
async fn a_foreign_approval_is_404_on_both_sides(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Cross Co").await;
    let me =
        common::seed_portal_contact(&pool, company, "me@example.com", &["Support Contact"]).await;
    let sibling =
        common::seed_portal_contact(&pool, company, "sib@example.com", &["Support Contact"]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;
    let t1 = seed_ticket(&pool, company, admin_id, "Sibling's").await;
    let t2 = seed_ticket(&pool, company, admin_id, "Staff's").await;
    let t3 = seed_ticket(&pool, company, admin_id, "Mine").await;
    let theirs = address_to_contact(&app, &staff, t1, sibling.id, "x").await;
    let theirs = Uuid::parse_str(theirs["id"].as_str().unwrap()).unwrap();
    let staff_row: Value = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{t2}/approvals")))
        .bearer_auth(&staff)
        .json(&json!({ "approver_user_id": admin_id, "notes": "staff decides" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let staff_row = Uuid::parse_str(staff_row["id"].as_str().unwrap()).unwrap();
    let mine = address_to_contact(&app, &staff, t3, me.id, "x").await;
    let mine = Uuid::parse_str(mine["id"].as_str().unwrap()).unwrap();

    let token = common::contact_token(&app, &me).await;
    let (_, body) = pending(&app, &token).await;
    assert_eq!(ids(&body), vec![mine.to_string()]);
    for (name, id) in [
        ("sibling", theirs),
        ("staff", staff_row),
        ("unknown", Uuid::new_v4()),
    ] {
        let resp = decide(&app, &token, id, "approve").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{name}");
    }
    // Staff: the admin's queue holds the row addressed to it and not
    // the contact's, and deciding the contact's row is refused.
    let (_, staff_queue) = pending(&app, &staff).await;
    assert_eq!(ids(&staff_queue), vec![staff_row.to_string()]);
    let resp = decide(&app, &staff, mine, "approve").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Nothing moved.
    let status: String = sqlx::query_scalar("SELECT status FROM ticket_approvals WHERE id = $1")
        .bind(theirs)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "pending");
}

// Without `approvals:decide` (Read-Only and Billing Contact lack it)
// both routes are 403; anonymous is 401.
#[sqlx::test]
async fn without_approvals_decide_the_routes_are_403(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Cap Co").await;
    let reader =
        common::seed_portal_contact(&pool, company, "ro@example.com", &["Read-Only"]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;
    let t = seed_ticket(&pool, company, admin_id, "Gated").await;
    let row = address_to_contact(&app, &staff, t, reader.id, "x").await;
    let row = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();

    let token = common::contact_token(&app, &reader).await;
    let (status, _) = pending(&app, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        decide(&app, &token, row, "approve").await.status(),
        StatusCode::FORBIDDEN
    );
    let anon = app
        .client
        .get(app.url("/api/v1/approvals/pending"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
}

// The create path refuses a contact that is not a portal user of the
// tenant, and refuses two approver kinds at once.
#[sqlx::test]
async fn addressing_an_approval_validates_the_contact(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company(&pool, "Validate Co").await;
    let me =
        common::seed_portal_contact(&pool, company, "me@example.com", &["Support Contact"]).await;
    let app = common::boot(pool.clone()).await;
    let staff = common::login(&app, &email, &password).await;
    let t = seed_ticket(&pool, company, admin_id, "Validate").await;
    let post = |body: Value| {
        app.client
            .post(app.url(&format!("/api/v1/tickets/{t}/approvals")))
            .bearer_auth(&staff)
            .json(&body)
            .send()
    };
    let unknown = post(json!({ "approver_contact_id": Uuid::new_v4() }))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    let two = post(json!({ "approver_contact_id": me.id, "approver_role": "admin" }))
        .await
        .unwrap();
    assert_eq!(two.status(), StatusCode::BAD_REQUEST);
    let none = post(json!({ "notes": "nobody" })).await.unwrap();
    assert_eq!(none.status(), StatusCode::BAD_REQUEST);
    let ok = post(json!({ "approver_contact_id": me.id })).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}
