//! Integration tests for the knowledge base route group (PMS-79).
//!
//! Drives the staff-facing endpoints under `/api/v1/kb` through the real
//! router (legacy HS256 bearer auth, same harness as `tests/contacts.rs`).
//! Covers the working components implemented for the KB story:
//!
//! - category + article create happy path
//! - publishing stamps `published_at`; drafts leave it null
//! - editing content appends a new version (the version list grows)
//! - restoring a prior version brings its content back as a NEW version
//! - pg_trgm search finds an article by a fuzzy term
//! - duplicate per-tenant slug is rejected (409)
//! - helpful / not_helpful bump the counters
//!
//! The portal-visible feed lives on the portal tree at
//! `GET /api/v1/portal/kb` (behind `PortalAuthMiddleware` /
//! `RequirePortalAuth`); the agent tree no longer carries a
//! `/kb/articles/portal` route. Two tests cover it:
//!
//! - `portal_kb_feed_requires_portal_token_and_scopes_results` drives the
//!   real portal JWT auth end-to-end: anon / bad-token requests are 401,
//!   and a valid portal token returns only the contact's tenant + company
//!   published portal-visible articles.
//! - `portal_feed_company_scoping` pins the same SQL visibility/scoping at
//!   the service level via a direct `KbService` call.

mod common;

use sqlx::PgPool;

/// Create a category through the API and return its id.
#[allow(dead_code)]
async fn create_category(app: &common::TestApp, token: &str, name: &str, slug: &str) -> String {
    let body = serde_json::json!({ "name": name, "slug": slug });
    let resp = app
        .client
        .post(app.url("/api/v1/kb/categories"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create category");
    assert!(
        resp.status().is_success(),
        "create category should 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("create category JSON");
    v["id"]
        .as_str()
        .expect("created category has an id")
        .to_string()
}

/// Create an article through the API and return the full JSON body.
#[allow(dead_code)]
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

/// Seed a kb_articles row directly via SQL (bypassing the API) so a test
/// can stage portal-feed fixtures with explicit visibility / status /
/// company_ids. `published_at` is stamped only when `status` is
/// `published`, matching the service's create path.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn seed_kb_article(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    author_id: uuid::Uuid,
    slug: &str,
    visibility: &str,
    status: &str,
    company_ids: &[uuid::Uuid],
) {
    sqlx::query(
        r#"INSERT INTO kb_articles
           (tenant_id, title, slug, content, visibility, status, author_id,
            company_ids, published_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                   CASE WHEN $6 = 'published' THEN NOW() ELSE NULL END)"#,
    )
    .bind(tenant_id)
    .bind(slug)
    .bind(slug)
    .bind("body")
    .bind(visibility)
    .bind(status)
    .bind(author_id)
    // Bind as an owned Vec<Uuid> -> Postgres UUID[] (matches the
    // `&Vec<Uuid>` array-bind pattern used in contacts::service).
    .bind(company_ids.to_vec())
    .execute(pool)
    .await
    .expect("seed kb article");
}

#[sqlx::test]
async fn category_and_article_crud_happy_path(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let category_id = create_category(&app, &token, "Networking", "networking").await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Reset the router",
            "slug": "reset-the-router",
            "content": "Hold the reset button for ten seconds.",
            "category_id": category_id,
            "visibility": "public",
            "status": "draft",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("article id").to_string();
    assert_eq!(article["title"].as_str(), Some("Reset the router"));
    assert_eq!(article["status"].as_str(), Some("draft"));
    // Draft must not be stamped with published_at.
    assert!(
        article["published_at"].is_null(),
        "draft article should have null published_at, got {:?}",
        article["published_at"]
    );

    // GET round-trips.
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get article");
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = get_resp.json().await.expect("get article JSON");
    assert_eq!(got["slug"].as_str(), Some("reset-the-router"));

    // LIST contains it.
    let list_resp = app
        .client
        .get(app.url("/api/v1/kb/articles"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list articles");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let list: serde_json::Value = list_resp.json().await.expect("list articles JSON");
    let items = list["data"].as_array().expect("list has data array");
    assert!(
        items.iter().any(|a| a["id"].as_str() == Some(&article_id)),
        "article list should contain the created article"
    );
}

#[sqlx::test]
async fn publishing_stamps_published_at(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // Create as draft: published_at null.
    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Backups 101",
            "slug": "backups-101",
            "content": "Follow the 3-2-1 rule.",
            "status": "draft",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("article id").to_string();
    assert!(
        article["published_at"].is_null(),
        "draft starts unpublished"
    );

    // Transition to published: published_at gets stamped.
    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "status": "published" }))
        .send()
        .await
        .expect("send publish");
    assert!(put_resp.status().is_success());
    let published: serde_json::Value = put_resp.json().await.expect("publish JSON");
    assert_eq!(published["status"].as_str(), Some("published"));
    let first_published_at = published["published_at"]
        .as_str()
        .expect("published article has a published_at timestamp")
        .to_string();

    // A later edit that keeps it published must NOT move published_at.
    let put2 = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "content": "Follow the 3-2-1-1-0 rule." }))
        .send()
        .await
        .expect("send second edit");
    assert!(put2.status().is_success());
    let edited: serde_json::Value = put2.json().await.expect("second edit JSON");
    assert_eq!(
        edited["published_at"].as_str(),
        Some(first_published_at.as_str()),
        "published_at must be immutable once set"
    );
}

#[sqlx::test]
async fn create_as_published_stamps_published_at(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Already live",
            "slug": "already-live",
            "content": "Published straight away.",
            "status": "published",
        }),
    )
    .await;
    assert_eq!(article["status"].as_str(), Some("published"));
    assert!(
        article["published_at"].is_string(),
        "create-as-published should stamp published_at, got {:?}",
        article["published_at"]
    );
}

/// Pull the version list for an article and return (total, data array).
#[allow(dead_code)]
async fn versions(app: &common::TestApp, token: &str, article_id: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article_id}/versions")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send list versions");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json().await.expect("versions JSON")
}

#[sqlx::test]
async fn editing_content_appends_version(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Versioned doc",
            "slug": "versioned-doc",
            "content": "v1 content",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("article id").to_string();

    // Creation seeds version 1.
    let v0 = versions(&app, &token, &article_id).await;
    assert_eq!(v0["meta"]["total"].as_u64(), Some(1), "creation seeds v1");

    // Editing the content appends version 2.
    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "content": "v2 content" }))
        .send()
        .await
        .expect("send edit content");
    assert!(put_resp.status().is_success());

    let v1 = versions(&app, &token, &article_id).await;
    assert_eq!(
        v1["meta"]["total"].as_u64(),
        Some(2),
        "editing content should append a version"
    );
    // Versions are ordered version_number DESC; the newest holds v2.
    let newest = &v1["data"].as_array().expect("versions data")[0];
    assert_eq!(newest["version_number"].as_i64(), Some(2));
    assert_eq!(newest["content"].as_str(), Some("v2 content"));
}

#[sqlx::test]
async fn restore_brings_back_prior_version_as_new_version(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Restore me",
            "slug": "restore-me",
            "content": "original content",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("article id").to_string();

    // Edit to v2 so there is a prior (v1) snapshot to restore.
    let put_resp = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "content": "edited content" }))
        .send()
        .await
        .expect("send edit");
    assert!(put_resp.status().is_success());

    // Restore version 1.
    let restore_resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/kb/articles/{article_id}/versions/1/restore"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send restore");
    assert!(
        restore_resp.status().is_success(),
        "restore should 2xx, got {}",
        restore_resp.status()
    );
    let restored: serde_json::Value = restore_resp.json().await.expect("restore JSON");
    assert_eq!(
        restored["content"].as_str(),
        Some("original content"),
        "restore should bring back v1's content onto the article"
    );

    // The restore must land as a NEW monotonic version (v3), not mutate
    // history: v1 (original) + v2 (edit) + v3 (restore) = 3.
    let v = versions(&app, &token, &article_id).await;
    assert_eq!(
        v["meta"]["total"].as_u64(),
        Some(3),
        "restore should append a new version, not overwrite"
    );
    let newest = &v["data"].as_array().expect("versions data")[0];
    assert_eq!(newest["version_number"].as_i64(), Some(3));
    assert_eq!(newest["content"].as_str(), Some("original content"));

    // Independent GET proves the live article carries the restored body.
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get after restore");
    let got: serde_json::Value = get_resp.json().await.expect("get JSON");
    assert_eq!(got["content"].as_str(), Some("original content"));
}

#[sqlx::test]
async fn trigram_search_finds_article_by_fuzzy_term(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Configuring the VPN gateway",
            "slug": "configuring-the-vpn-gateway",
            "content": "Steps to configure the corporate VPN gateway endpoint.",
            "status": "published",
        }),
    )
    .await;

    // A misspelled term ("gatewayy", an extra trailing char on the word
    // "gateway" that appears in both the title and body) should still
    // match via pg_trgm word_similarity against the
    // (title || ' ' || content) GIN index.
    let resp = app
        .client
        .get(app.url("/api/v1/kb/articles?q=gatewayy"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send fuzzy search");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("search JSON");
    let items = body["data"].as_array().expect("search data array");
    assert!(
        items
            .iter()
            .any(|a| a["slug"].as_str() == Some("configuring-the-vpn-gateway")),
        "trigram search for 'gatewayy' should return the VPN gateway article, got {items:?}"
    );
}

#[sqlx::test]
async fn duplicate_slug_is_rejected(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // First article with the slug succeeds.
    create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "First",
            "slug": "dup-slug",
            "content": "first body",
        }),
    )
    .await;

    // Second article reusing the slug within the tenant is rejected.
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Second",
            "slug": "dup-slug",
            "content": "second body",
        }))
        .send()
        .await
        .expect("send duplicate-slug create");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "duplicate per-tenant slug should be 409, got {}",
        resp.status()
    );
}

#[sqlx::test]
async fn helpful_and_not_helpful_increment_counters(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Rate me",
            "slug": "rate-me",
            "content": "Was this helpful?",
        }),
    )
    .await;
    let article_id = article["id"].as_str().expect("article id").to_string();
    assert_eq!(article["helpful_count"].as_i64(), Some(0));
    assert_eq!(article["not_helpful_count"].as_i64(), Some(0));

    // helpful twice -> 2
    for _ in 0..2 {
        let resp = app
            .client
            .post(app.url(&format!("/api/v1/kb/articles/{article_id}/helpful")))
            .bearer_auth(&token)
            .send()
            .await
            .expect("send helpful");
        assert!(resp.status().is_success(), "helpful should 2xx");
    }
    // not_helpful once -> 1
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/kb/articles/{article_id}/not_helpful")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send not_helpful");
    assert!(resp.status().is_success(), "not_helpful should 2xx");
    let feedback: serde_json::Value = resp.json().await.expect("not_helpful JSON");
    assert_eq!(feedback["not_helpful_count"].as_i64(), Some(1));

    // Independent GET confirms both counters persisted.
    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get after feedback");
    let got: serde_json::Value = get_resp.json().await.expect("get JSON");
    assert_eq!(
        got["helpful_count"].as_i64(),
        Some(2),
        "two helpful clicks should total 2"
    );
    assert_eq!(
        got["not_helpful_count"].as_i64(),
        Some(1),
        "one not_helpful click should total 1"
    );
}

/// Seed a portal-enabled contact under a company and return
/// `(company_id, email, plaintext_password)`. The contact is created with
/// `is_portal_user = TRUE` and a real Argon2 hash so it can drive
/// `POST /api/v1/portal/auth/login`. The company is created under the
/// given tenant first because `contacts.company_id` is `NOT NULL` with an
/// FK to `companies`.
#[allow(dead_code)]
async fn seed_portal_contact(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    email: &str,
) -> (uuid::Uuid, String, String) {
    let company_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company_id)
        .bind(tenant_id)
        .bind(format!("Company for {email}"))
        .execute(pool)
        .await
        .expect("seed portal company");

    let password = "portal-password-12345".to_string();
    let password_hash = mokosh_server::utils::crypto::hash_password(&password)
        .expect("hash portal contact password");

    sqlx::query(
        r#"INSERT INTO contacts
           (tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash, status)
           VALUES ($1, $2, 'Portal', 'User', $3, TRUE, $4, 'active')"#,
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("seed portal contact");

    (company_id, email.to_string(), password)
}

/// Log a portal contact in and return its access token.
#[allow(dead_code)]
async fn portal_login(
    app: &common::TestApp,
    tenant_slug: &str,
    email: &str,
    password: &str,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": tenant_slug,
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("send portal login");
    assert!(
        resp.status().is_success(),
        "portal login should 2xx, got {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("portal login JSON");
    v["access_token"]
        .as_str()
        .expect("portal login returns an access_token")
        .to_string()
}

/// End-to-end portal-JWT protection on the portal KB feed
/// (`GET /api/v1/portal/kb`).
///
/// The portal feed is the only portal-visible KB surface; the agent tree
/// no longer carries a `/kb/articles/portal` route (it was mislabeled and
/// agent-authed). This test pins the contract the `mokosh-apps` portal
/// page depends on:
///
/// - a request WITHOUT a portal token is rejected (401), not served an
///   empty 200;
/// - a request WITH a valid portal token returns only the authenticated
///   contact's tenant + company published portal-visible articles:
///   `public` published articles and `client_specific` published articles
///   whose `company_ids` include the contact's company. Drafts, other
///   companies' `client_specific` articles, and other tenants' articles
///   are all excluded. Scoping is derived from the JWT claims
///   (`CurrentContact.tenant_id` / `company_id`), never from client input.
#[sqlx::test]
async fn portal_kb_feed_requires_portal_token_and_scopes_results(pool: PgPool) {
    // Author user (FK target for kb_articles.author_id).
    let (author_id, _email, _password) = common::seed_admin(&pool).await;
    let tenant_id = common::DEFAULT_TENANT_ID;

    // Portal contact under company A in the default tenant (slug "default").
    let (company_a, contact_email, contact_password) =
        seed_portal_contact(&pool, tenant_id, "portal-contact@example.com").await;
    // A second company in the same tenant to prove cross-company scoping.
    let company_b = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(company_b)
        .bind(tenant_id)
        .bind("Company B")
        .execute(&pool)
        .await
        .expect("seed company B");

    // A different tenant + company to prove tenant scoping.
    let (other_tenant, other_author, _e, _p) =
        common::seed_tenant_with_admin(&pool, "other-tenant").await;
    let other_company = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(other_company)
        .bind(other_tenant)
        .bind("Other Tenant Co")
        .execute(&pool)
        .await
        .expect("seed other-tenant company");

    // Fixtures in the contact's tenant.
    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "pub-art",
        "public",
        "published",
        &[],
    )
    .await;
    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "a-art",
        "client_specific",
        "published",
        &[company_a],
    )
    .await;
    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "b-art",
        "client_specific",
        "published",
        &[company_b],
    )
    .await;
    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "draft-art",
        "public",
        "draft",
        &[],
    )
    .await;
    // Same-tenant public article that should be visible.
    // A published public article in ANOTHER tenant must never appear.
    seed_kb_article(
        &pool,
        other_tenant,
        other_author,
        "other-tenant-pub",
        "public",
        "published",
        &[],
    )
    .await;

    let app = common::boot(pool).await;

    // 1) No token -> 401. The feed must not serve an empty 200 to anon.
    let unauth = app
        .client
        .get(app.url("/api/v1/portal/kb?page=1&per_page=100"))
        .send()
        .await
        .expect("send unauth portal kb");
    assert_eq!(
        unauth.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "portal kb feed without a token must be 401, got {}",
        unauth.status()
    );

    // 2) Garbage bearer -> 401 (decode fails).
    let bad = app
        .client
        .get(app.url("/api/v1/portal/kb?page=1&per_page=100"))
        .bearer_auth("not-a-real-jwt")
        .send()
        .await
        .expect("send bad-token portal kb");
    assert_eq!(
        bad.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "portal kb feed with a bad token must be 401, got {}",
        bad.status()
    );

    // 3) Valid portal token -> 200, scoped to tenant + company A.
    let token = portal_login(&app, "default", &contact_email, &contact_password).await;
    let resp = app
        .client
        .get(app.url("/api/v1/portal/kb?page=1&per_page=100"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send authed portal kb");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "authed portal kb feed should 200, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("portal kb JSON");
    let items = body["data"].as_array().expect("portal kb data array");
    let slugs: Vec<&str> = items
        .iter()
        .map(|a| a["slug"].as_str().expect("article slug"))
        .collect();

    assert_eq!(
        body["meta"]["total"].as_u64(),
        Some(2),
        "company A should see exactly 2 articles: {slugs:?}"
    );
    assert!(
        slugs.contains(&"pub-art"),
        "public article visible: {slugs:?}"
    );
    assert!(
        slugs.contains(&"a-art"),
        "A's client_specific article visible: {slugs:?}"
    );
    assert!(
        !slugs.contains(&"b-art"),
        "B's client_specific article must be hidden from A: {slugs:?}"
    );
    assert!(
        !slugs.contains(&"draft-art"),
        "draft must be hidden from the portal feed: {slugs:?}"
    );
    assert!(
        !slugs.contains(&"other-tenant-pub"),
        "another tenant's article must never appear: {slugs:?}"
    );
}

/// Service-level pin for the portal feed visibility rules (PMS-84).
///
/// Seeds three published articles directly via SQL (public,
/// client_specific scoped to company A, client_specific scoped to company
/// B) plus one draft, then calls `KbService::list_portal_articles_for_company`
/// for company A. The feed must contain the public article and A's
/// client_specific article, and must exclude B's client_specific article
/// and the draft. This exercises the exact query the portal `/kb` route
/// delegates to; the route itself just threads the contact's company_id
/// from the JWT claim.
#[sqlx::test]
async fn portal_feed_company_scoping(pool: PgPool) {
    use mokosh_server::utils::pagination::PaginationParams;

    let tenant_id = common::DEFAULT_TENANT_ID;
    let company_a = uuid::Uuid::new_v4();
    let company_b = uuid::Uuid::new_v4();

    // An author user is required by the FK on kb_articles.author_id.
    let (author_id, _email, _password) = common::seed_admin(&pool).await;

    // Seed companies so the (nullable) FK target exists; company rows are
    // required by contacts but kb_articles.company_ids is a free UUID[]
    // with no FK, so we only need the ids. Insert minimal company rows
    // anyway to mirror real data.
    for (cid, name) in [(company_a, "Company A"), (company_b, "Company B")] {
        sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
            .bind(cid)
            .bind(tenant_id)
            .bind(name)
            .execute(&pool)
            .await
            .expect("seed company");
    }

    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "pub-art",
        "public",
        "published",
        &[],
    )
    .await;
    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "a-art",
        "client_specific",
        "published",
        &[company_a],
    )
    .await;
    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "b-art",
        "client_specific",
        "published",
        &[company_b],
    )
    .await;
    // A public but unpublished (draft) article must be excluded.
    seed_kb_article(
        &pool,
        tenant_id,
        author_id,
        "draft-art",
        "public",
        "draft",
        &[],
    )
    .await;

    let db = mokosh_server::Database::from_pool(pool.clone());
    let kb = mokosh_server::modules::knowledge_base::KbService::new(db);

    // Build explicit params: PaginationParams::default() leaves page /
    // per_page at the Rust zero-default (serde defaults only apply when
    // deserializing), which clamps to LIMIT 1 and would truncate the
    // result set under test.
    let pagination = PaginationParams {
        page: 1,
        per_page: 25,
        sort: None,
        sort_dir: "desc".to_string(),
    };
    let (items, total) = kb
        .list_portal_articles_for_company(tenant_id, company_a, &pagination)
        .await
        .expect("portal feed query");

    let slugs: Vec<&str> = items.iter().map(|a| a.slug.as_str()).collect();
    assert_eq!(
        total, 2,
        "company A should see exactly 2 articles: {slugs:?}"
    );
    assert!(slugs.contains(&"pub-art"), "public article is visible");
    assert!(
        slugs.contains(&"a-art"),
        "A's client_specific article is visible"
    );
    assert!(
        !slugs.contains(&"b-art"),
        "B's client_specific article must be hidden from A"
    );
    assert!(
        !slugs.contains(&"draft-art"),
        "draft article must be hidden from the portal feed"
    );
}
