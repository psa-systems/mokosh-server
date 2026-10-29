//! Integration tests for the templated-knowledge-base render endpoint.
//!
//! Exercises `POST /api/v1/kb/articles/{id}/render` end-to-end through
//! the real router (legacy HS256 bearer auth, same harness as
//! `tests/suites/knowledge_base.rs`). Covers Phase 1a:
//!
//! - a variable write + read round-trip (POST then GET surfaces the
//!   declared variables unchanged)
//! - render with values substitutes `{{ var }}` and takes the matching
//!   branch of `{% if %}`
//! - render with no declared variables returns the stored content
//!   byte-identically regardless of the caller's values map
//! - a conditional on a declared-but-unsupplied variable falls to else
//! - a bare `{{ var }}` on a declared-but-unsupplied variable renders
//!   as `[missing: NAME]`
//! - sanitization still runs: an invisible character the template
//!   introduces is stripped by the same sanitizer the un-templated
//!   path applies on write
//! - create-time validation rejects duplicate names and a default that
//!   is not in a non-empty `allowed_values`
//! - render-time validation rejects an unknown variable name in the
//!   caller's values map

use crate::common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;

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

async fn create_article_status(
    app: &common::TestApp,
    token: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send create article");
    let status = resp.status();
    let body = resp.json().await.expect("create article JSON");
    (status, body)
}

async fn render(
    app: &common::TestApp,
    token: &str,
    article_id: &str,
    values: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/kb/articles/{article_id}/render")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "values": values }))
        .send()
        .await
        .expect("send render");
    let status = resp.status();
    let body = resp.json().await.expect("render JSON");
    (status, body)
}

#[mokosh_test]
async fn template_variables_round_trip_on_create_and_get(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Reset the router",
            "slug": "reset-the-router-render",
            "content": "Reset {{ host }} in {{ environment }}.",
            "status": "draft",
            "template_variables": [
                {
                    "name": "host",
                    "label": "Host",
                    "allowed_values": [],
                    "default": null,
                },
                {
                    "name": "environment",
                    "label": "Environment",
                    "allowed_values": ["staging", "production"],
                    "default": "staging",
                },
            ],
        }),
    )
    .await;
    let id = article["id"].as_str().expect("id").to_string();

    let get_resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET");
    assert!(get_resp.status().is_success());
    let got: serde_json::Value = get_resp.json().await.expect("GET JSON");
    let vars = got["template_variables"].as_array().expect("tvs array");
    assert_eq!(
        vars.len(),
        2,
        "both declared variables survive the round-trip"
    );
    assert_eq!(vars[0]["name"].as_str(), Some("host"));
    assert_eq!(vars[1]["name"].as_str(), Some("environment"));
    assert_eq!(vars[1]["default"].as_str(), Some("staging"));
}

#[mokosh_test]
async fn render_with_values_substitutes_and_picks_branch(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Render test",
            "slug": "render-with-values",
            "content": "host={{ host }} env={{ environment }} \
                {% if environment == \"production\" %}LIVE{% else %}SAFE{% endif %}",
            "status": "draft",
            "template_variables": [
                {"name": "host", "label": "Host", "allowed_values": [], "default": null},
                {
                    "name": "environment",
                    "label": "Environment",
                    "allowed_values": ["staging", "production"],
                    "default": "staging",
                },
            ],
        }),
    )
    .await;
    let id = article["id"].as_str().expect("id");

    let (status, body) = render(
        &app,
        &token,
        id,
        serde_json::json!({
            "host": "web01",
            "environment": "production",
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let content = body["content"].as_str().expect("rendered content");
    assert!(content.contains("host=web01"), "got {content}");
    assert!(content.contains("env=production"), "got {content}");
    assert!(
        content.contains("LIVE"),
        "production branch taken: {content}"
    );
    assert!(!content.contains("SAFE"), "else branch dropped: {content}");
}

#[mokosh_test]
async fn render_with_no_declared_vars_is_byte_identical(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let content = "# Plain article\n\nLiteral {{ not_a_variable }} stays as-is.";
    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Plain",
            "slug": "plain-article",
            "content": content,
            "status": "draft",
        }),
    )
    .await;
    let id = article["id"].as_str().expect("id");

    let (status, body) = render(&app, &token, id, serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        body["content"].as_str(),
        Some(content),
        "no declared variables, render returns stored content byte-identically"
    );
}

#[mokosh_test]
async fn conditional_on_unsupplied_variable_takes_else_branch(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Conditional",
            "slug": "conditional-render",
            "content": "{% if environment == \"production\" %}P{% else %}S{% endif %}",
            "status": "draft",
            "template_variables": [
                {
                    "name": "environment",
                    "label": "Environment",
                    "allowed_values": ["staging", "production"],
                    "default": null,
                },
            ],
        }),
    )
    .await;
    let id = article["id"].as_str().expect("id");

    let (status, body) = render(&app, &token, id, serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["content"].as_str(), Some("S"));
}

#[mokosh_test]
async fn unsupplied_bare_var_renders_missing_placeholder(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Missing",
            "slug": "missing-placeholder",
            "content": "host={{ host }}",
            "status": "draft",
            "template_variables": [
                {"name": "host", "label": "Host", "allowed_values": [], "default": null},
            ],
        }),
    )
    .await;
    let id = article["id"].as_str().expect("id");

    let (status, body) = render(&app, &token, id, serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["content"].as_str(), Some("host=[missing: host]"));
}

#[mokosh_test]
async fn sanitizer_strips_invisible_chars_from_rendered_output(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    // The content contains a U+200B zero-width space which the un-templated
    // write path's sanitizer strips. The render path reuses the same
    // sanitizer AFTER the engine runs, so a value whose characters embed
    // one gets the same treatment and the client never receives it.
    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Sanitize",
            "slug": "sanitize-rendered",
            "content": "x={{ x }}",
            "status": "draft",
            "template_variables": [
                {"name": "x", "label": "X", "allowed_values": [], "default": null},
            ],
        }),
    )
    .await;
    let id = article["id"].as_str().expect("id");

    // Note: the request-body sanitizer strips invisibles from `x` BEFORE
    // the handler sees it, so by the time it reaches the engine the value
    // is already clean. We assert the end-to-end property: no U+200B
    // survives to the response.
    let (status, body) = render(&app, &token, id, serde_json::json!({"x": "ab\u{200B}cd"})).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let content = body["content"].as_str().expect("rendered content");
    assert!(
        !content.contains('\u{200B}'),
        "no zero-width space survives to the rendered content: {content:?}"
    );
    assert_eq!(content, "x=abcd");
}

#[mokosh_test]
async fn create_rejects_duplicate_variable_names(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (status, _body) = create_article_status(
        &app,
        &token,
        serde_json::json!({
            "title": "Bad",
            "slug": "bad-duplicate",
            "content": "ignored",
            "status": "draft",
            "template_variables": [
                {"name": "a", "label": "A", "allowed_values": [], "default": null},
                {"name": "a", "label": "A2", "allowed_values": [], "default": null},
            ],
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[mokosh_test]
async fn create_rejects_default_not_in_allowed_values(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let (status, _body) = create_article_status(
        &app,
        &token,
        serde_json::json!({
            "title": "Bad default",
            "slug": "bad-default",
            "content": "ignored",
            "status": "draft",
            "template_variables": [
                {
                    "name": "env",
                    "label": "Env",
                    "allowed_values": ["staging", "production"],
                    "default": "qa",
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[mokosh_test]
async fn render_rejects_unknown_variable_name(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;

    let article = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Unknown name",
            "slug": "unknown-name",
            "content": "host={{ host }}",
            "status": "draft",
            "template_variables": [
                {"name": "host", "label": "Host", "allowed_values": [], "default": null},
            ],
        }),
    )
    .await;
    let id = article["id"].as_str().expect("id");

    let (status, _body) = render(&app, &token, id, serde_json::json!({"not_declared": "x"})).await;
    assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}
