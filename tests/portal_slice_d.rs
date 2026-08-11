//! PMS-729 phase 2 §7 slice D: approvals (I7), data export (I15),
//! multi-contact view (I13), delegation (I18).

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

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

async fn seed_portal_contact(pool: &PgPool, company_id: Uuid, email: &str) -> Uuid {
    let hash = mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash password");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, $4, 'Contact', $5, TRUE, $6)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email.split('@').next().unwrap_or("Port"))
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

async fn login(app: &common::TestApp, email: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
            "password": PORTAL_PASSWORD,
        }))
        .send()
        .await
        .expect("login");
    assert!(resp.status().is_success());
    resp.json::<serde_json::Value>().await.expect("body")["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---- I13 -----------------------------------------------------------------

#[sqlx::test]
async fn company_roster_shows_siblings_flags_the_caller(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Roster Co").await;
    let other_company = seed_company(&pool, "Someone Else Co").await;
    let me = seed_portal_contact(&pool, company, "me@example.com").await;
    let _sib = seed_portal_contact(&pool, company, "sibling@example.com").await;
    // A contact at another company under the same tenant must never appear.
    let _stranger = seed_portal_contact(&pool, other_company, "stranger@example.com").await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/company/contacts"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 2, "expected 2 own-company rows: {body}");
    let mut you_hits = 0;
    for row in rows {
        assert!(row.get("phone").is_none(), "phone leaked");
        if row["is_you"].as_bool().unwrap_or(false) {
            you_hits += 1;
            assert_eq!(row["id"].as_str().unwrap(), me.to_string());
        }
        assert!(rows
            .iter()
            .all(|r| r["email"].as_str().unwrap() != "stranger@example.com"));
    }
    assert_eq!(
        you_hits, 1,
        "exactly one row should be flagged is_you: {body}"
    );
}

// ---- I7 ------------------------------------------------------------------

async fn seed_ticket_and_approval(
    pool: &PgPool,
    company: Uuid,
    admin_id: Uuid,
    contact_id: Uuid,
    ticket_title: &str,
) -> (Uuid, Uuid) {
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
        r#"INSERT INTO tickets (id, tenant_id, ticket_number, title, status_id, priority_id,
                                queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(ticket_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &ticket_id.to_string()[..8]))
    .bind(ticket_title)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    let approval_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO ticket_approvals
                (id, tenant_id, ticket_id, requested_by_id, approver_contact_id,
                 status, notes, target, entity_id)
           VALUES ($1, $2, $3, $4, $5, 'pending', 'Please approve', 'ticket', $3)"#,
    )
    .bind(approval_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(ticket_id)
    .bind(admin_id)
    .bind(contact_id)
    .execute(pool)
    .await
    .expect("seed approval");
    (ticket_id, approval_id)
}

#[sqlx::test]
async fn approvals_list_and_decide(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Approvals Co").await;
    let me = seed_portal_contact(&pool, company, "approve@example.com").await;
    let (_ticket, approval) =
        seed_ticket_and_approval(&pool, company, admin_id, me, "Server down").await;

    let token = login(&app, "approve@example.com").await;
    let list = app
        .client
        .get(app.url("/api/v1/portal/approvals"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(list.status().is_success());
    let body: serde_json::Value = list.json().await.unwrap();
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"].as_str().unwrap(), "pending");
    assert!(rows[0]["label"]
        .as_str()
        .unwrap_or_default()
        .contains("Server down"));

    // Decide.
    let decide = app
        .client
        .post(app.url(&format!("/api/v1/portal/approvals/{approval}/decide")))
        .bearer_auth(&token)
        .json(&serde_json::json!({"decision": "approve", "decision_notes": "OK"}))
        .send()
        .await
        .expect("decide");
    assert_eq!(decide.status(), reqwest::StatusCode::NO_CONTENT);

    // Second decide: 409 (already decided).
    let repeat = app
        .client
        .post(app.url(&format!("/api/v1/portal/approvals/{approval}/decide")))
        .bearer_auth(&token)
        .json(&serde_json::json!({"decision": "approve"}))
        .send()
        .await
        .expect("repeat");
    assert_eq!(repeat.status(), reqwest::StatusCode::CONFLICT);
}

#[sqlx::test]
async fn approvals_hide_cross_contact_rows(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Cross Co").await;
    let me = seed_portal_contact(&pool, company, "me@example.com").await;
    let sibling = seed_portal_contact(&pool, company, "sibling@example.com").await;
    // Assign the approval to the sibling; I should never see it.
    let (_t, stolen) =
        seed_ticket_and_approval(&pool, company, admin_id, sibling, "Sibling's ticket").await;
    let _ = me;

    let token = login(&app, "me@example.com").await;
    let list = app
        .client
        .get(app.url("/api/v1/portal/approvals"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body.as_array().unwrap().is_empty(),
        "sibling row leaked: {body}"
    );
    // Decide against stolen id: 404.
    let decide = app
        .client
        .post(app.url(&format!("/api/v1/portal/approvals/{stolen}/decide")))
        .bearer_auth(&token)
        .json(&serde_json::json!({"decision": "approve"}))
        .send()
        .await
        .expect("decide");
    assert_eq!(decide.status(), reqwest::StatusCode::NOT_FOUND);
}

// ---- I15 -----------------------------------------------------------------

#[sqlx::test]
async fn export_request_returns_queued_job_and_poll_returns_the_same(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Export Co").await;
    let _me = seed_portal_contact(&pool, company, "exp@example.com").await;
    let token = login(&app, "exp@example.com").await;

    let post = app
        .client
        .post(app.url("/api/v1/portal/export"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("post");
    assert_eq!(post.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = post.json().await.unwrap();
    let job_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["status"].as_str().unwrap(), "queued");

    let poll = app
        .client
        .get(app.url(&format!("/api/v1/portal/export/{job_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("poll");
    assert!(poll.status().is_success());
    let body: serde_json::Value = poll.json().await.unwrap();
    assert_eq!(body["id"].as_str().unwrap(), job_id);
    assert_eq!(body["status"].as_str().unwrap(), "queued");
}

#[sqlx::test]
async fn export_poll_returns_404_for_cross_contact_id(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Cross Co").await;
    let me = seed_portal_contact(&pool, company, "me@example.com").await;
    let sibling = seed_portal_contact(&pool, company, "sibling@example.com").await;
    let _ = me;
    let stolen = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO portal_exports (id, tenant_id, contact_id, company_id, status)
           VALUES ($1, $2, $3, $4, 'ready')"#,
    )
    .bind(stolen)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(sibling)
    .bind(company)
    .execute(&pool)
    .await
    .expect("seed sibling export");

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/portal/export/{stolen}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("poll");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ---- I18 -----------------------------------------------------------------

#[sqlx::test]
async fn delegation_grant_list_revoke(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Delegate Co").await;
    let _me = seed_portal_contact(&pool, company, "me@example.com").await;
    let dee = seed_portal_contact(&pool, company, "colleague@example.com").await;
    let token = login(&app, "me@example.com").await;

    // Grant.
    let grant = app
        .client
        .post(app.url("/api/v1/portal/company/delegations"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "delegatee_contact_id": dee.to_string(),
            "scope": {"tickets": true}
        }))
        .send()
        .await
        .expect("grant");
    assert_eq!(grant.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = grant.json().await.unwrap();
    let delegation_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(
        body["delegatee_email"].as_str().unwrap(),
        "colleague@example.com"
    );

    // List.
    let list = app
        .client
        .get(app.url("/api/v1/portal/company/delegations"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body.as_array().unwrap().len(), 1);

    // Revoke.
    let revoke = app
        .client
        .delete(app.url(&format!(
            "/api/v1/portal/company/delegations/{delegation_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoke.status(), reqwest::StatusCode::NO_CONTENT);

    // Re-list: row is gone (revoked rows never surface).
    let list_after = app
        .client
        .get(app.url("/api/v1/portal/company/delegations"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list after");
    let body: serde_json::Value = list_after.json().await.unwrap();
    assert!(body.as_array().unwrap().is_empty());
}

#[sqlx::test]
async fn delegation_grant_rejects_self_and_cross_company(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "Mine Co").await;
    let other_company = seed_company(&pool, "Other Co").await;
    let me = seed_portal_contact(&pool, mine, "me@example.com").await;
    let outsider = seed_portal_contact(&pool, other_company, "outside@example.com").await;
    let token = login(&app, "me@example.com").await;

    // Self.
    let self_grant = app
        .client
        .post(app.url("/api/v1/portal/company/delegations"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "delegatee_contact_id": me.to_string(),
            "scope": {}
        }))
        .send()
        .await
        .expect("self");
    assert!(self_grant.status().is_client_error());

    // Cross-company.
    let cross_grant = app
        .client
        .post(app.url("/api/v1/portal/company/delegations"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "delegatee_contact_id": outsider.to_string(),
            "scope": {}
        }))
        .send()
        .await
        .expect("cross");
    assert!(cross_grant.status().is_client_error());
}

// ---- shared 401 ---------------------------------------------------------

#[sqlx::test]
async fn slice_d_endpoints_require_a_portal_session(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    for path in [
        "/api/v1/portal/approvals",
        "/api/v1/portal/company/contacts",
        "/api/v1/portal/company/delegations",
    ] {
        let resp = app.client.get(app.url(path)).send().await.expect("send");
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED, "{path}");
    }
}
