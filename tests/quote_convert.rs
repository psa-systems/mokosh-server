//! PMS-674: integration tests for converting an accepted quote into a
//! Project.
//!
//! Pins the guarantees the ticket calls out:
//!   - Conversion maps the quote's client, name, scope, and budget onto
//!     the project and links both rows.
//!   - It is refused from any state other than `accepted`.
//!   - Converting twice returns the same project and leaves exactly one.
//!   - Two concurrent conversions still produce exactly one project, with
//!     no 500 leaking to either caller.
//!   - It is atomic: a failing project insert leaves the quote unconverted.
//!   - The conversion is audited.

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const PORTAL_PASSWORD: &str = "portal-password-12345";

async fn seed_company_named(pool: &PgPool, name: &str) -> Uuid {
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
    let id = Uuid::new_v4();
    let hash =
        mokosh_server::utils::crypto::hash_password(PORTAL_PASSWORD).expect("hash portal password");
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, 'Portal', 'Contact', $4, TRUE, $5)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("seed portal contact");
    id
}

async fn portal_token(app: &common::TestApp, email: &str) -> String {
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
        .expect("send portal login");
    assert!(resp.status().is_success(), "portal login should 2xx");
    let body: Value = resp.json().await.expect("portal login JSON");
    body["access_token"].as_str().expect("token").to_string()
}

/// Build a quote and walk it all the way to `accepted` through the real
/// routes, so the fixture exercises the same path production does.
async fn accepted_quote(
    app: &common::TestApp,
    pool: &PgPool,
    token: &str,
    company: Uuid,
    email: &str,
) -> String {
    let contact = seed_portal_contact(pool, company, email).await;
    let quote: Value = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company,
            "billing_contact_id": contact,
            "title": "Provide LLM access to Employees",
            "description": "Set up Private Network, set up a web service with SSL, configure users + LLM software.",
            "lines": [
                {"line_type":"service","description":"Network build","quantity":"2","unit_price":"500"},
                {"line_type":"labour","description":"Configuration","quantity":"1","unit_price":"250"}
            ],
        }))
        .send()
        .await
        .expect("create quote")
        .json()
        .await
        .expect("quote body");
    let quote_id = quote["id"].as_str().unwrap().to_string();

    for status in ["submitted", "approved"] {
        let r = app
            .client
            .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
            .bearer_auth(token)
            .json(&serde_json::json!({ "status": status }))
            .send()
            .await
            .expect("advance");
        assert_eq!(r.status(), StatusCode::OK);
    }
    let sent = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/send")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send");
    assert_eq!(sent.status(), StatusCode::OK);

    let portal = portal_token(app, email).await;
    let accepted = app
        .client
        .post(app.url(&format!("/api/v1/portal/quotes/{quote_id}/accept")))
        .bearer_auth(&portal)
        .send()
        .await
        .expect("accept");
    assert_eq!(accepted.status(), StatusCode::OK);
    quote_id
}

#[sqlx::test]
async fn accepted_quote_converts_into_a_mapped_project(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let quote_id = accepted_quote(&app, &pool, &token, company, "convert@example.com").await;

    let converted: Value = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "project_manager_id": admin_id,
            "start_date": "2026-08-01",
            "target_end_date": "2026-09-30",
        }))
        .send()
        .await
        .expect("convert")
        .json()
        .await
        .expect("convert body");

    assert_eq!(converted["status"], "converted");
    let project_id = converted["converted_project_id"]
        .as_str()
        .expect("converted_project_id is set");

    // The project carries the quote's client, name, scope, and budget.
    let project: Value = app
        .client
        .get(app.url(&format!("/api/v1/projects/{project_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get project")
        .json()
        .await
        .expect("project body");
    assert_eq!(project["name"], "Provide LLM access to Employees");
    assert_eq!(project["company_id"], company.to_string());
    assert_eq!(project["status"], "planning");
    assert_eq!(project["project_type"], "client");
    assert_eq!(
        project["budget_amount"], "1250.00",
        "the project budget is the quote total"
    );
    assert_eq!(
        project["billing_method"], "fixed_price",
        "an accepted quote is a fixed price, not the projects-table default"
    );
    assert_eq!(project["project_manager_id"], admin_id.to_string());
    assert!(project["description"]
        .as_str()
        .unwrap()
        .contains("Private Network"));

    // Both the project creation and the quote transition are audited.
    let project_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE entity_type = 'projects' AND entity_id = $1",
    )
    .bind(Uuid::parse_str(project_id).unwrap())
    .fetch_one(&pool)
    .await
    .expect("count project audits");
    assert!(project_audits > 0, "project creation must be audited");
}

#[sqlx::test]
async fn conversion_is_refused_before_the_client_accepts(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let quote: Value = app
        .client
        .post(app.url("/api/v1/quotes"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "company_id": company, "title": "Unaccepted" }))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .expect("body");
    let quote_id = quote["id"].as_str().unwrap().to_string();

    // Draft.
    let from_draft = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("convert draft");
    assert_eq!(from_draft.status(), StatusCode::CONFLICT);

    // Approved but not yet accepted by the client: internal sign-off is
    // not the client's signature.
    for status in ["submitted", "approved"] {
        app.client
            .put(app.url(&format!("/api/v1/quotes/{quote_id}")))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "status": status }))
            .send()
            .await
            .expect("advance");
    }
    let from_approved = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("convert approved");
    assert_eq!(
        from_approved.status(),
        StatusCode::CONFLICT,
        "internal approval is not client acceptance"
    );

    // Nothing was created along the way.
    let projects: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("count projects");
    assert_eq!(projects, 0, "a refused conversion creates no project");
}

#[sqlx::test]
async fn converting_twice_returns_the_same_project(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let quote_id = accepted_quote(&app, &pool, &token, company, "twice@example.com").await;

    let first: Value = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("first convert")
        .json()
        .await
        .expect("body");

    // A double-clicked Convert button is not an error.
    let second_resp = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("second convert");
    assert_eq!(second_resp.status(), StatusCode::OK);
    let second: Value = second_resp.json().await.expect("body");

    assert_eq!(
        first["converted_project_id"], second["converted_project_id"],
        "the second conversion returns the same project"
    );

    let projects: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("count projects");
    assert_eq!(projects, 1, "exactly one project exists");
}

#[sqlx::test]
async fn concurrent_conversions_produce_exactly_one_project(pool: PgPool) {
    // The `SELECT ... FOR UPDATE` on the quote row is what makes this
    // safe. Without it both requests read `accepted` and each inserts its
    // own project, and the UNIQUE on `converted_project_id` would not stop
    // them: that constraint prevents two QUOTES sharing one project, which
    // is a different failure.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let quote_id = accepted_quote(&app, &pool, &token, company, "race@example.com").await;

    // Enough racers, all launched before any is awaited, to make the
    // windows genuinely overlap. Two requests are not enough: they
    // serialise on the connection pool and the test passes even with the
    // lock removed, which is false confidence.
    let url = app.url(&format!("/api/v1/quotes/{quote_id}/convert"));
    let mut racers = Vec::new();
    for _ in 0..16 {
        let client = app.client.clone();
        let url = url.clone();
        let token = token.clone();
        racers.push(tokio::spawn(async move {
            client.post(&url).bearer_auth(&token).send().await
        }));
    }
    let mut results = Vec::new();
    for r in racers {
        results.push(r.await.expect("racer task"));
    }

    // No caller may see a 500: whichever loses the race must get the
    // existing link back, not a database error.
    let mut project_ids = std::collections::HashSet::new();
    for (i, resp) in results.into_iter().enumerate() {
        let resp = resp.unwrap_or_else(|e| panic!("racer {i}: {e}"));
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "racer {i} should 200, got {}",
            resp.status()
        );
        let body: Value = resp.json().await.expect("racer body");
        project_ids.insert(
            body["converted_project_id"]
                .as_str()
                .expect("converted_project_id")
                .to_string(),
        );
    }
    assert_eq!(
        project_ids.len(),
        1,
        "every racer must agree on one project; got {project_ids:?}"
    );

    let projects: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("count projects");
    assert_eq!(projects, 1, "the race must leave exactly one project");
}

#[sqlx::test]
async fn a_failed_project_insert_leaves_the_quote_unconverted(pool: PgPool) {
    // Atomicity: the project insert and the quote transition share one
    // transaction. Point `project_manager_id` at a user that does not
    // exist so the FK rejects the insert, and assert the quote did not
    // move.
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let quote_id = accepted_quote(&app, &pool, &token, company, "atomic@example.com").await;

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "project_manager_id": Uuid::new_v4() }))
        .send()
        .await
        .expect("convert with bad manager");
    assert!(
        !resp.status().is_success(),
        "a violated FK must not succeed; got {}",
        resp.status()
    );

    let status: String = sqlx::query_scalar("SELECT status FROM quotes WHERE id = $1")
        .bind(Uuid::parse_str(&quote_id).unwrap())
        .fetch_one(&pool)
        .await
        .expect("quote status");
    assert_eq!(
        status, "accepted",
        "the quote must not be left converted with no project behind it"
    );
    let linked: Option<Uuid> =
        sqlx::query_scalar("SELECT converted_project_id FROM quotes WHERE id = $1")
            .bind(Uuid::parse_str(&quote_id).unwrap())
            .fetch_one(&pool)
            .await
            .expect("link");
    assert!(linked.is_none(), "no dangling project link");

    let projects: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("count projects");
    assert_eq!(projects, 0, "the rolled-back insert left no project");
}

#[sqlx::test]
async fn convert_rejects_a_malformed_body(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = seed_company_named(&pool, "Client A").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let quote_id = accepted_quote(&app, &pool, &token, company, "validate@example.com").await;

    // Unknown billing method: caught by the validator as a 422 rather than
    // reaching the database CHECK as a 500.
    let bad_method = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "billing_method": "barter" }))
        .send()
        .await
        .expect("bad billing method");
    assert_eq!(bad_method.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // End before start.
    let bad_dates = app
        .client
        .post(app.url(&format!("/api/v1/quotes/{quote_id}/convert")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "start_date": "2026-09-30",
            "target_end_date": "2026-08-01",
        }))
        .send()
        .await
        .expect("bad dates");
    assert_eq!(bad_dates.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // The quote is untouched by the rejected attempts.
    let status: String = sqlx::query_scalar("SELECT status FROM quotes WHERE id = $1")
        .bind(Uuid::parse_str(&quote_id).unwrap())
        .fetch_one(&pool)
        .await
        .expect("status");
    assert_eq!(status, "accepted");
}
