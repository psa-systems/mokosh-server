//! End-to-end tests for the KB parent link and the list company filter.

mod common;

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

/// A create with `parent_article_id` writes the link and it round-trips
/// on read. Refuses a self-reference and refuses a foreign parent id.
#[mokosh_test]
async fn parent_article_id_round_trips_and_refuses_bad_shapes(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let parent = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Onboarding a new workstation",
            "slug": "onboard-workstation",
            "content": "# Generic runbook",
            "visibility": "internal",
            "status": "published",
        }),
    )
    .await;
    let parent_id = parent["id"].as_str().expect("parent id");

    // Child names the parent explicitly.
    let child = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Onboarding an Acme workstation",
            "slug": "acme-onboard-workstation",
            "content": "# Acme runbook",
            "visibility": "internal",
            "status": "published",
            "parent_article_id": parent_id,
        }),
    )
    .await;
    assert_eq!(child["parent_article_id"].as_str(), Some(parent_id));

    // Read-back on the child preserves the link.
    let child_id = child["id"].as_str().expect("child id");
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{child_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send get");
    let one: serde_json::Value = resp.json().await.expect("get JSON");
    assert_eq!(one["parent_article_id"].as_str(), Some(parent_id));

    // Self-reference on update is refused.
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{child_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "parent_article_id": child_id }))
        .send()
        .await
        .expect("send self-parent update");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);

    // A parent id that does not exist in this tenant is refused.
    let bogus = uuid::Uuid::new_v4();
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Bad parent",
            "slug": "bad-parent",
            "content": "x",
            "visibility": "internal",
            "status": "draft",
            "parent_article_id": bogus,
        }))
        .send()
        .await
        .expect("send create");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

/// Filtering by `company_id` narrows the list to the client-specific
/// articles that carry that company. A `public` / `internal` article
/// with no company scope stays out.
#[mokosh_test]
async fn list_filters_by_company_id(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_a = common::seed_company_named(&pool, "Acme").await;
    let company_b = common::seed_company_named(&pool, "Globex").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let generic = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Onboarding a new workstation",
            "slug": "onboard-workstation",
            "content": "# Runbook",
            "visibility": "internal",
            "status": "published",
        }),
    )
    .await;
    let generic_id = generic["id"].as_str().expect("id");

    // Acme variant: client_specific with parent link.
    create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Onboarding an Acme workstation",
            "slug": "acme-onboarding",
            "content": "# Acme",
            "visibility": "client_specific",
            "status": "published",
            "company_ids": [company_a],
            "parent_article_id": generic_id,
        }),
    )
    .await;
    // Globex variant.
    create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Onboarding a Globex workstation",
            "slug": "globex-onboarding",
            "content": "# Globex",
            "visibility": "client_specific",
            "status": "published",
            "company_ids": [company_b],
            "parent_article_id": generic_id,
        }),
    )
    .await;

    // Filter by Acme: only the Acme variant returns.
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles?company_id={company_a}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list");
    let body: serde_json::Value = resp.json().await.expect("list JSON");
    let items = body["data"].as_array().expect("data array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["title"], "Onboarding an Acme workstation");

    // Filter by parent id: both variants come back, generic does not.
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/kb/articles?parent_article_id={generic_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list");
    let body: serde_json::Value = resp.json().await.expect("list JSON");
    let items = body["data"].as_array().expect("data array");
    assert_eq!(items.len(), 2);
    let titles: Vec<&str> = items.iter().filter_map(|i| i["title"].as_str()).collect();
    assert!(titles.iter().any(|t| t.contains("Acme")));
    assert!(titles.iter().any(|t| t.contains("Globex")));
    // The generic article is NOT in the parent-filtered set.
    assert!(!titles
        .iter()
        .any(|t| t.contains("Onboarding a new workstation")));

    // Company + parent together: exactly the Acme variant.
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/kb/articles?company_id={company_a}&parent_article_id={generic_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send list");
    let body: serde_json::Value = resp.json().await.expect("list JSON");
    let items = body["data"].as_array().expect("data array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["title"], "Onboarding an Acme workstation");
}

/// PMS-816: a variant of a variant collapses the "generic / client-specific"
/// shape into an untyped tree. A create pointing at a parent that itself has
/// a parent must be refused.
#[mokosh_test]
async fn a_parent_that_already_has_a_parent_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company_named(&pool, "Acme").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let generic = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Generic",
            "slug": "generic",
            "content": "x",
            "visibility": "internal",
            "status": "draft",
        }),
    )
    .await;
    let generic_id = generic["id"].as_str().expect("id");

    let variant = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Variant",
            "slug": "variant",
            "content": "x",
            "visibility": "client_specific",
            "status": "draft",
            "company_ids": [company],
            "parent_article_id": generic_id,
        }),
    )
    .await;
    let variant_id = variant["id"].as_str().expect("id");

    // Try to make a third article's parent be the variant (which already
    // has a parent). The service refuses with a 422 naming the field.
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "title": "Grand-variant",
            "slug": "grand-variant",
            "content": "x",
            "visibility": "client_specific",
            "status": "draft",
            "company_ids": [company],
            "parent_article_id": variant_id,
        }))
        .send()
        .await
        .expect("send create");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("err JSON");
    let dump = body.to_string();
    assert!(
        dump.contains("parent_article_id"),
        "error names the field: {dump}"
    );
}

/// PMS-816: an article that already has children cannot be given a parent
/// of its own, for the same one-level-only reason. An update that would
/// turn an existing parent into a child must be refused.
#[mokosh_test]
async fn giving_an_article_with_children_a_parent_is_refused(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company = common::seed_company_named(&pool, "Acme").await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let parent = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Parent",
            "slug": "parent",
            "content": "x",
            "visibility": "internal",
            "status": "draft",
        }),
    )
    .await;
    let parent_id = parent["id"].as_str().expect("id");

    create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Child",
            "slug": "child",
            "content": "x",
            "visibility": "client_specific",
            "status": "draft",
            "company_ids": [company],
            "parent_article_id": parent_id,
        }),
    )
    .await;

    let other_top_level = create_article(
        &app,
        &token,
        serde_json::json!({
            "title": "Other top level",
            "slug": "other-top-level",
            "content": "x",
            "visibility": "internal",
            "status": "draft",
        }),
    )
    .await;
    let other_id = other_top_level["id"].as_str().expect("id");

    // Try to point `parent` at `other_top_level`. Refused: parent has a child,
    // so it cannot itself become a child.
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{parent_id}")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "parent_article_id": other_id }))
        .send()
        .await
        .expect("send update");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let body: serde_json::Value = resp.json().await.expect("err JSON");
    let dump = body.to_string();
    assert!(
        dump.contains("parent_article_id"),
        "error names the field: {dump}"
    );
}
