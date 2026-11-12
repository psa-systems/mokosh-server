//! Integration tests for KB article executions on tickets.
//!
//! Exercises `POST /api/v1/tickets/{ticket_id}/kb-executions`,
//! `GET /api/v1/tickets/{ticket_id}/kb-executions`,
//! `GET /api/v1/kb-executions/{id}`, and
//! `PATCH /api/v1/kb-executions/{id}/steps/{index}` end-to-end through
//! the real router (legacy HS256 bearer auth, same harness as
//! `tests/suites/kb_render.rs`).

use crate::common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_article(
    app: &common::TestApp,
    token: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create article");
    assert!(
        resp.status().is_success(),
        "create article should 2xx, got {}",
        resp.status()
    );
    resp.json().await.expect("create article JSON")
}

async fn create_execution(
    app: &common::TestApp,
    token: &str,
    ticket_id: Uuid,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/tickets/{ticket_id}/kb-executions")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create execution");
    let status = resp.status();
    let body = resp.json().await.expect("create execution JSON");
    (status, body)
}

async fn seed_ticket(pool: &PgPool, admin_id: Uuid) -> Uuid {
    let company_id = common::seed_company(pool).await;
    let (ticket_id, _note_id) = common::seed_ticket_and_note(pool, admin_id, company_id).await;
    ticket_id
}

#[mokosh_test]
async fn create_execution_parses_task_steps_and_persists_row(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Checklist",
            "slug": "checklist-exec",
            "content": "# Steps\n\n- [ ] First\n- [ ] Second\n- [x] Third already done\n",
            "status": "draft",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("article id").to_string();

    let (status, body) = create_execution(
        &app,
        &token,
        ticket_id,
        serde_json::json!({ "article_id": article_id, "values": {} }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let steps = body["steps"].as_array().expect("steps array");
    assert_eq!(steps.len(), 3, "three task-list items parsed");
    assert_eq!(steps[0]["text"].as_str(), Some("First"));
    assert_eq!(steps[0]["index"].as_i64(), Some(0));
    assert!(steps[0]["checked_at"].is_null());
    assert_eq!(steps[2]["text"].as_str(), Some("Third already done"));
    assert!(
        !steps[2]["checked_at"].is_null(),
        "pre-rendered [x] step starts checked"
    );
    assert_eq!(
        steps[2]["checked_by_user_id"]
            .as_str()
            .map(|s| s.to_string()),
        Some(admin_id.to_string()),
        "pre-checked step is attributed to the creator"
    );
    assert_eq!(
        body["ticket_id"].as_str(),
        Some(ticket_id.to_string().as_str())
    );
    assert!(
        !body["article_version_id"].is_null(),
        "article_version_id snapshotted from the article's version row"
    );
}

#[mokosh_test]
async fn prose_article_creates_execution_with_zero_steps(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Pure prose",
            "slug": "pure-prose",
            "content": "# Context\n\nJust some prose. No checkboxes anywhere.\n",
            "status": "draft",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("article id");

    let (status, body) = create_execution(
        &app,
        &token,
        ticket_id,
        serde_json::json!({ "article_id": article_id }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(
        body["steps"].as_array().map(Vec::len),
        Some(0),
        "an execution record exists even for a pure-prose article"
    );
}

#[mokosh_test]
async fn check_and_uncheck_are_idempotent(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Idempotent",
            "slug": "idempotent-check",
            "content": "- [ ] One\n",
            "status": "draft",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("id");
    let (_s, body) = create_execution(
        &app,
        &token,
        ticket_id,
        serde_json::json!({ "article_id": article_id }),
    )
    .await;
    let exec_id = body["id"].as_str().expect("execution id");

    // First check: records the admin and a timestamp.
    let resp = app
        .client
        .patch(app.url(&format!("/api/v1/kb-executions/{exec_id}/steps/0")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "checked": true }))
        .send()
        .await
        .expect("send PATCH check");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let step: serde_json::Value = resp.json().await.expect("step JSON");
    let first_checked_at = step["checked_at"]
        .as_str()
        .expect("checked_at set")
        .to_string();
    assert_eq!(
        step["checked_by_user_id"].as_str(),
        Some(admin_id.to_string().as_str())
    );

    // Second check: no-op; preserves original timestamp and checker.
    let resp2 = app
        .client
        .patch(app.url(&format!("/api/v1/kb-executions/{exec_id}/steps/0")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "checked": true }))
        .send()
        .await
        .expect("send second check");
    let step2: serde_json::Value = resp2.json().await.expect("step JSON");
    assert_eq!(
        step2["checked_at"].as_str(),
        Some(first_checked_at.as_str()),
        "double-check keeps the original checked_at"
    );

    // Uncheck: both fields clear.
    let resp3 = app
        .client
        .patch(app.url(&format!("/api/v1/kb-executions/{exec_id}/steps/0")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "checked": false }))
        .send()
        .await
        .expect("send uncheck");
    let step3: serde_json::Value = resp3.json().await.expect("step JSON");
    assert!(step3["checked_at"].is_null(), "uncheck clears checked_at");
    assert!(
        step3["checked_by_user_id"].is_null(),
        "uncheck clears checked_by_user_id"
    );

    // Second uncheck: no-op.
    let resp4 = app
        .client
        .patch(app.url(&format!("/api/v1/kb-executions/{exec_id}/steps/0")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "checked": false }))
        .send()
        .await
        .expect("send second uncheck");
    assert_eq!(resp4.status(), reqwest::StatusCode::OK);
    let step4: serde_json::Value = resp4.json().await.expect("step JSON");
    assert!(step4["checked_at"].is_null());
}

#[mokosh_test]
async fn list_rolls_up_total_and_checked_counts(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Three steps",
            "slug": "three-steps",
            "content": "- [ ] A\n- [x] B\n- [ ] C\n",
            "status": "draft",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("id");
    let (_s, body) = create_execution(
        &app,
        &token,
        ticket_id,
        serde_json::json!({ "article_id": article_id }),
    )
    .await;
    let exec_id = body["id"].as_str().expect("id");

    // Check one more step.
    let _ = app
        .client
        .patch(app.url(&format!("/api/v1/kb-executions/{exec_id}/steps/0")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "checked": true }))
        .send()
        .await
        .expect("check first");

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/tickets/{ticket_id}/kb-executions")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let rows: Vec<serde_json::Value> = resp.json().await.expect("list JSON");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["total_steps"].as_i64(), Some(3));
    assert_eq!(rows[0]["checked_steps"].as_i64(), Some(2));
    assert_eq!(rows[0]["article_name"].as_str(), Some("Three steps"));
}

#[mokosh_test]
async fn variable_values_round_trip_on_response(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Templated",
            "slug": "templated-exec",
            "content": "- [ ] Reboot {{ host }}\n- [ ] Verify {{ host }} is up\n",
            "status": "draft",
            "template_variables": [
                { "name": "host", "label": "Host", "allowed_values": [], "default": null },
            ],
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("id");

    let (status, body) = create_execution(
        &app,
        &token,
        ticket_id,
        serde_json::json!({ "article_id": article_id, "values": { "host": "web01" } }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(
        body["variable_values"]["host"].as_str(),
        Some("web01"),
        "the caller's values are persisted on the execution row"
    );
    let steps = body["steps"].as_array().expect("steps");
    assert!(
        steps[0]["text"].as_str().unwrap().contains("web01"),
        "the rendered step text carries the substituted value"
    );
}

#[mokosh_test]
async fn unknown_article_id_returns_404(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (status, _body) = create_execution(
        &app,
        &token,
        ticket_id,
        serde_json::json!({ "article_id": Uuid::new_v4() }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

#[mokosh_test]
async fn render_422_propagates_through_create(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Picky",
            "slug": "picky-article",
            "content": "- [ ] Do {{ env }}\n",
            "status": "draft",
            "template_variables": [
                {
                    "name": "env",
                    "label": "Env",
                    "allowed_values": ["staging", "production"],
                    "default": null,
                },
            ],
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("id");

    // `env=qa` is not in allowed_values -> Phase 1a render returns 422.
    let (status, _body) = create_execution(
        &app,
        &token,
        ticket_id,
        serde_json::json!({ "article_id": article_id, "values": { "env": "qa" } }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[mokosh_test]
async fn tenant_two_cannot_read_tenant_one_execution(pool: PgPool) {
    // Tenant 1: create an execution.
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let ticket_id = seed_ticket(&pool, admin_id).await;

    // Tenant 2: a separate admin + login against a different slug.
    let (_other_tenant_id, _other_user_id, other_email, other_password) =
        common::seed_tenant_with_admin(&pool, "kbexec-other").await;

    let app = common::boot(pool).await;

    let token_one = common::login(&app, &email, &password).await;
    let token_two =
        common::login_with_tenant(&app, &other_email, &other_password, "kbexec-other").await;

    let article = create_article(
        &app,
        &token_one,
        serde_json::json!({
            "title": "Secret",
            "slug": "tenant-one-secret",
            "content": "- [ ] Keep it tenant-one\n",
            "status": "draft",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("id");
    let (_s, exec) = create_execution(
        &app,
        &token_one,
        ticket_id,
        serde_json::json!({ "article_id": article_id }),
    )
    .await;
    let exec_id = exec["id"].as_str().expect("id");

    // Tenant two attempts to read it: 404 (not 403), the standard
    // RLS-backed existence confusion the rest of the KB routes use.
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/kb-executions/{exec_id}")))
        .bearer_auth(&token_two)
        .send()
        .await
        .expect("send cross-tenant read");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}
