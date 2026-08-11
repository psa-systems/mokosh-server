//! PMS-729 phase 2 §7 slice A / I14: `/portal/search?q=...` HTTP tests.
//!
//! Pins the four-section wire shape (tickets, invoices, quotes,
//! kb_articles) plus the company-scoping D18 requires: a match in
//! another company under the same tenant NEVER appears in the caller's
//! result set, and internal-only KB articles are hidden.

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
        VALUES ($1, $2, $3, 'Port', 'Al', $4, TRUE, $5)
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
    let body: serde_json::Value = resp.json().await.expect("login body");
    body["access_token"].as_str().unwrap().to_string()
}

async fn seed_ticket(pool: &PgPool, company_id: Uuid, admin_id: Uuid, title: &str) -> Uuid {
    let id = Uuid::new_v4();
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
    sqlx::query(
        r#"
        INSERT INTO tickets
            (id, tenant_id, ticket_number, title, status_id, priority_id,
             queue_id, company_id, created_by_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
    .bind(title)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    id
}

async fn seed_kb_article(
    pool: &PgPool,
    author_id: Uuid,
    title: &str,
    visibility: &str,
    company_ids: Option<Vec<Uuid>>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO kb_articles
            (id, tenant_id, title, slug, content, summary,
             visibility, company_ids, status, author_id, published_at)
        VALUES ($1, $2, $3, $4, 'body', 'summary', $5, $6, 'published', $7, NOW())
        "#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(title)
    .bind(format!("slug-{}", &id.to_string()[..8]))
    .bind(visibility)
    .bind(company_ids.unwrap_or_default())
    .bind(author_id)
    .execute(pool)
    .await
    .expect("seed kb");
    id
}

// -- tests -----------------------------------------------------------------

/// Happy path: a matching ticket + KB article surface in the grouped
/// response, counts reflect the totals, no other section leaks.
#[sqlx::test]
async fn portal_search_returns_grouped_matches_scoped_to_the_company(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Search Co").await;
    let _c = seed_portal_contact(&pool, company, "search@example.com").await;
    let _t1 = seed_ticket(&pool, company, admin_id, "Printer offline in HQ").await;
    let _t2 = seed_ticket(&pool, company, admin_id, "Unrelated matter").await;
    let _kb = seed_kb_article(
        &pool,
        admin_id,
        "How to power-cycle a printer",
        "public",
        None,
    )
    .await;

    let token = login(&app, "search@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/search?q=printer"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send search");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();

    let tickets = body["tickets"].as_array().unwrap();
    assert_eq!(tickets.len(), 1, "one ticket expected: {body}");
    assert!(tickets[0]["label"]
        .as_str()
        .unwrap()
        .contains("Printer offline"));

    let kb = body["kb_articles"].as_array().unwrap();
    assert_eq!(kb.len(), 1);
    assert_eq!(
        kb[0]["label"].as_str().unwrap(),
        "How to power-cycle a printer"
    );

    assert_eq!(body["counts"]["tickets"].as_i64().unwrap(), 1);
    assert_eq!(body["counts"]["kb_articles"].as_i64().unwrap(), 1);
    assert_eq!(body["counts"]["invoices"].as_i64().unwrap(), 0);
    assert_eq!(body["counts"]["quotes"].as_i64().unwrap(), 0);
}

/// Cross-company tickets never appear in the caller's result set.
#[sqlx::test]
async fn portal_search_never_returns_cross_company_matches(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let mine = seed_company(&pool, "My Co").await;
    let other = seed_company(&pool, "Other Co").await;
    let _c = seed_portal_contact(&pool, mine, "me@example.com").await;
    // Seed a matching ticket in OTHER company only. Never mine.
    let _t = seed_ticket(&pool, other, admin_id, "Printer down").await;

    let token = login(&app, "me@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/search?q=Printer"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["tickets"].as_array().unwrap().is_empty(),
        "cross-company ticket leaked: {body}"
    );
    assert_eq!(body["counts"]["tickets"].as_i64().unwrap(), 0);
}

/// Internal-visibility KB article is hidden from the portal search;
/// client_specific with the caller's company id in `company_ids`
/// shows up.
#[sqlx::test]
async fn portal_search_respects_kb_visibility_rules(pool: PgPool) {
    let (admin_id, _e, _p) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Vis Co").await;
    let _c = seed_portal_contact(&pool, company, "vis@example.com").await;
    let _internal =
        seed_kb_article(&pool, admin_id, "Internal admin playbook", "internal", None).await;
    let _client_specific = seed_kb_article(
        &pool,
        admin_id,
        "Playbook for Vis Co only",
        "client_specific",
        Some(vec![company]),
    )
    .await;
    let _foreign_client_specific = seed_kb_article(
        &pool,
        admin_id,
        "Playbook for someone else",
        "client_specific",
        Some(vec![Uuid::new_v4()]),
    )
    .await;

    let token = login(&app, "vis@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/search?q=Playbook"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let kb = body["kb_articles"].as_array().unwrap();
    assert_eq!(
        kb.len(),
        1,
        "only the caller's client_specific playbook should surface: {body}"
    );
    assert_eq!(kb[0]["label"].as_str().unwrap(), "Playbook for Vis Co only");
}

/// A blank query returns the default (empty) response, not a 400. The
/// SPA can safely fire on every keystroke without special-casing empty.
#[sqlx::test]
async fn portal_search_returns_empty_default_for_blank_query(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let company = seed_company(&pool, "Blank Co").await;
    let _c = seed_portal_contact(&pool, company, "blank@example.com").await;

    let token = login(&app, "blank@example.com").await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/search?q=%20%20"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["tickets"].as_array().unwrap().is_empty());
    assert!(body["invoices"].as_array().unwrap().is_empty());
    assert!(body["quotes"].as_array().unwrap().is_empty());
    assert!(body["kb_articles"].as_array().unwrap().is_empty());
    assert_eq!(body["counts"]["tickets"].as_i64().unwrap(), 0);
}

/// Missing bearer: 401.
#[sqlx::test]
async fn portal_search_requires_a_portal_session(pool: PgPool) {
    let _ = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/search?q=hello"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
