//! PMS-1128: staff discussion on a knowledge base article.
//!
//! - a technician opens a thread, an admin replies, the tree comes back two
//!   deep and oldest first, with names and never bare ids
//! - the author edits their own comment and `edited_at` says so; a manager
//!   cannot edit another person's comment; an admin can
//! - a reply must answer a live root on the same article and carries no
//!   anchor
//! - any staff role resolves and reopens a root; a reply cannot be resolved
//! - a soft-deleted comment keeps its place with an empty body, cannot be
//!   edited or resolved again, and its replies survive
//! - an anchored root records the article's current version
//! - a contact holding `kb:read` on a published public article gets 401 on
//!   every comment route: there is no customer-visible comment

mod common;

use sqlx::PgPool;

async fn create_article(app: &common::TestApp, token: &str, slug: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "title": slug,
            "slug": slug,
            "content": "# Body\n\nSome text.\n",
            "visibility": "public",
            "status": "published",
        }))
        .send()
        .await
        .expect("send create article");
    assert!(
        resp.status().is_success(),
        "create article {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("article JSON");
    v["id"].as_str().expect("article id").to_string()
}

async fn post_comment(
    app: &common::TestApp,
    token: &str,
    article_id: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    app.client
        .post(app.url(&format!("/api/v1/kb/articles/{article_id}/comments")))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("send comment")
}

async fn comments(app: &common::TestApp, token: &str, article_id: &str) -> serde_json::Value {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article_id}/comments")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send list comments");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json().await.expect("comments JSON")
}

#[sqlx::test]
async fn a_thread_is_two_deep_named_and_oldest_first(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "kb-tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &email, &password).await;
    let tech = common::login(&app, &tech_email, &tech_password).await;
    let article_id = create_article(&app, &admin, "threads").await;

    let root = post_comment(
        &app,
        &tech,
        &article_id,
        serde_json::json!({ "body": "  Step 3 is out of date.  " }),
    )
    .await;
    assert_eq!(root.status(), reqwest::StatusCode::CREATED);
    let root: serde_json::Value = root.json().await.expect("root JSON");
    assert_eq!(
        root["body"].as_str(),
        Some("Step 3 is out of date."),
        "trimmed"
    );
    assert_eq!(root["author_name"].as_str(), Some("Test User"));
    assert!(root["parent_id"].is_null());
    assert!(
        root["anchor_version"].is_null(),
        "no anchor, no anchor version"
    );
    let root_id = root["id"].as_str().expect("root id").to_string();

    let reply = post_comment(
        &app,
        &admin,
        &article_id,
        serde_json::json!({ "body": "Fixed in v4.", "parent_id": root_id }),
    )
    .await;
    assert_eq!(reply.status(), reqwest::StatusCode::CREATED);
    let reply: serde_json::Value = reply.json().await.expect("reply JSON");
    let reply_id = reply["id"].as_str().expect("reply id").to_string();
    assert_eq!(reply["parent_id"].as_str(), Some(root_id.as_str()));

    let second_root = post_comment(
        &app,
        &admin,
        &article_id,
        serde_json::json!({ "body": "Separate point." }),
    )
    .await;
    assert_eq!(second_root.status(), reqwest::StatusCode::CREATED);

    let tree = comments(&app, &tech, &article_id).await;
    let roots = tree.as_array().expect("roots");
    assert_eq!(roots.len(), 2, "{tree}");
    assert_eq!(
        roots[0]["id"].as_str(),
        Some(root_id.as_str()),
        "oldest first"
    );
    let replies = roots[0]["replies"].as_array().expect("replies");
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["id"].as_str(), Some(reply_id.as_str()));
    assert_eq!(replies[0]["author_name"].as_str(), Some("Test Admin"));
    assert!(roots[1]["replies"].as_array().expect("replies").is_empty());

    // A reply to a reply, a reply with an anchor, and a reply to a comment on
    // another article are all refused with the field named.
    for (body, field) in [
        (
            serde_json::json!({ "body": "nested", "parent_id": reply_id }),
            "parent_id",
        ),
        (
            serde_json::json!({ "body": "anchored reply", "parent_id": root_id, "anchor": { "exact": "x" } }),
            "anchor",
        ),
    ] {
        let resp = post_comment(&app, &admin, &article_id, body).await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            "{field}"
        );
        let text = resp.text().await.expect("body");
        assert!(text.contains(field), "{field} named in {text}");
    }
    let other_article = create_article(&app, &admin, "other").await;
    let resp = post_comment(
        &app,
        &admin,
        &other_article,
        serde_json::json!({ "body": "wrong article", "parent_id": root_id }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[sqlx::test]
async fn the_author_or_an_admin_edits_and_deletes_and_a_manager_does_not(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "kb-tech@example.com",
        "technician",
    )
    .await;
    let (_mgr_id, mgr_email, mgr_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "kb-mgr@example.com",
        "manager",
    )
    .await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &email, &password).await;
    let tech = common::login(&app, &tech_email, &tech_password).await;
    let mgr = common::login(&app, &mgr_email, &mgr_password).await;
    let article_id = create_article(&app, &admin, "edits").await;

    let root: serde_json::Value = post_comment(
        &app,
        &tech,
        &article_id,
        serde_json::json!({ "body": "first" }),
    )
    .await
    .json()
    .await
    .expect("root JSON");
    let root_id = root["id"].as_str().expect("id").to_string();
    assert!(root["edited_at"].is_null());

    let put = |token: String, body: &'static str| {
        let app = &app;
        let root_id = root_id.clone();
        async move {
            app.client
                .put(app.url(&format!("/api/v1/kb/comments/{root_id}")))
                .bearer_auth(&token)
                .json(&serde_json::json!({ "body": body }))
                .send()
                .await
                .expect("send edit")
        }
    };
    let own = put(tech.clone(), "first, corrected").await;
    assert_eq!(own.status(), reqwest::StatusCode::OK);
    let own: serde_json::Value = own.json().await.expect("edit JSON");
    assert_eq!(own["body"].as_str(), Some("first, corrected"));
    assert!(own["edited_at"].is_string(), "edited_at set: {own}");

    let by_manager = put(mgr.clone(), "manager rewrite").await;
    assert_eq!(by_manager.status(), reqwest::StatusCode::FORBIDDEN);

    let by_admin = put(admin.clone(), "admin rewrite").await;
    assert_eq!(by_admin.status(), reqwest::StatusCode::OK);

    // Delete: the manager may not, the author may; the row keeps its place
    // with an empty body and cannot be edited or resolved again.
    let reply: serde_json::Value = post_comment(
        &app,
        &admin,
        &article_id,
        serde_json::json!({ "body": "a reply that must survive", "parent_id": root_id }),
    )
    .await
    .json()
    .await
    .expect("reply JSON");
    let del = |token: String| {
        let app = &app;
        let root_id = root_id.clone();
        async move {
            app.client
                .delete(app.url(&format!("/api/v1/kb/comments/{root_id}")))
                .bearer_auth(&token)
                .send()
                .await
                .expect("send delete")
        }
    };
    assert_eq!(
        del(mgr.clone()).await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        del(tech.clone()).await.status(),
        reqwest::StatusCode::NO_CONTENT
    );

    let tree = comments(&app, &admin, &article_id).await;
    let roots = tree.as_array().expect("roots");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0]["deleted"].as_bool(), Some(true));
    assert_eq!(roots[0]["body"].as_str(), Some(""), "the text is gone");
    assert_eq!(
        roots[0]["author_name"].as_str(),
        Some("Test User"),
        "the place is kept"
    );
    let replies = roots[0]["replies"].as_array().expect("replies");
    assert_eq!(
        replies[0]["id"].as_str(),
        reply["id"].as_str(),
        "the reply survives"
    );

    assert_eq!(
        put(admin.clone(), "necromancy").await.status(),
        reqwest::StatusCode::CONFLICT
    );
    let resolve = app
        .client
        .post(app.url(&format!("/api/v1/kb/comments/{root_id}/resolve")))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("send resolve");
    assert_eq!(resolve.status(), reqwest::StatusCode::CONFLICT);
}

#[sqlx::test]
async fn any_staff_role_resolves_a_root_and_a_reply_cannot_be_resolved(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let (_tech_id, tech_email, tech_password) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "kb-tech@example.com",
        "technician",
    )
    .await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &email, &password).await;
    let tech = common::login(&app, &tech_email, &tech_password).await;
    let article_id = create_article(&app, &admin, "resolve").await;

    let root: serde_json::Value = post_comment(
        &app,
        &admin,
        &article_id,
        serde_json::json!({ "body": "an issue" }),
    )
    .await
    .json()
    .await
    .expect("root JSON");
    let root_id = root["id"].as_str().expect("id").to_string();
    let reply: serde_json::Value = post_comment(
        &app,
        &admin,
        &article_id,
        serde_json::json!({ "body": "done", "parent_id": root_id }),
    )
    .await
    .json()
    .await
    .expect("reply JSON");
    let reply_id = reply["id"].as_str().expect("id");

    let resolved = app
        .client
        .post(app.url(&format!("/api/v1/kb/comments/{root_id}/resolve")))
        .bearer_auth(&tech)
        .send()
        .await
        .expect("send resolve");
    assert_eq!(resolved.status(), reqwest::StatusCode::OK);
    let resolved: serde_json::Value = resolved.json().await.expect("resolve JSON");
    assert!(resolved["resolved_at"].is_string());
    assert_eq!(resolved["resolved_by_name"].as_str(), Some("Test User"));

    let reopened = app
        .client
        .post(app.url(&format!("/api/v1/kb/comments/{root_id}/unresolve")))
        .bearer_auth(&tech)
        .send()
        .await
        .expect("send unresolve");
    assert_eq!(reopened.status(), reqwest::StatusCode::OK);
    let reopened: serde_json::Value = reopened.json().await.expect("unresolve JSON");
    assert!(reopened["resolved_at"].is_null());
    assert!(reopened["resolved_by_name"].is_null());

    let on_reply = app
        .client
        .post(app.url(&format!("/api/v1/kb/comments/{reply_id}/resolve")))
        .bearer_auth(&tech)
        .send()
        .await
        .expect("send resolve reply");
    assert_eq!(on_reply.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[sqlx::test]
async fn an_anchored_root_records_the_article_version_it_quotes(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &email, &password).await;
    let article_id = create_article(&app, &admin, "anchored").await;
    let put = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&admin)
        .json(&serde_json::json!({ "content": "# Body\n\nSome text, revised.\n" }))
        .send()
        .await
        .expect("send edit");
    assert!(put.status().is_success());

    let anchor = serde_json::json!({ "type": "TextQuoteSelector", "exact": "Some text, revised." });
    let root: serde_json::Value = post_comment(
        &app,
        &admin,
        &article_id,
        serde_json::json!({ "body": "about this line", "anchor": anchor }),
    )
    .await
    .json()
    .await
    .expect("root JSON");
    assert_eq!(root["anchor"], anchor, "stored and returned as given");
    assert_eq!(
        root["anchor_version"].as_i64(),
        Some(2),
        "the version the quote was taken from"
    );
}

#[sqlx::test]
async fn a_contact_never_sees_a_comment(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let contact = common::seed_portal_contact(
        &pool,
        company_id,
        "reader@example.com",
        &["Support Contact"],
    )
    .await;
    let app = common::boot(pool).await;
    let admin = common::login(&app, &email, &password).await;
    let article_id = create_article(&app, &admin, "customer-visible").await;
    let root: serde_json::Value = post_comment(
        &app,
        &admin,
        &article_id,
        serde_json::json!({ "body": "internal" }),
    )
    .await
    .json()
    .await
    .expect("root JSON");
    let root_id = root["id"].as_str().expect("id");

    let contact_token = common::contact_token(&app, &contact).await;
    // The contact can read the article itself...
    let article = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article_id}")))
        .bearer_auth(&contact_token)
        .send()
        .await
        .expect("send contact article read");
    assert_eq!(article.status(), reqwest::StatusCode::OK);

    // ...and not one comment route, read or write.
    let list = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article_id}/comments")))
        .bearer_auth(&contact_token)
        .send()
        .await
        .expect("send contact list");
    assert_eq!(list.status(), reqwest::StatusCode::UNAUTHORIZED);
    let post = post_comment(
        &app,
        &contact_token,
        &article_id,
        serde_json::json!({ "body": "hi" }),
    )
    .await;
    assert_eq!(post.status(), reqwest::StatusCode::UNAUTHORIZED);
    for path in [
        format!("/api/v1/kb/comments/{root_id}/resolve"),
        format!("/api/v1/kb/comments/{root_id}/unresolve"),
    ] {
        let resp = app
            .client
            .post(app.url(&path))
            .bearer_auth(&contact_token)
            .send()
            .await
            .expect("send contact resolve");
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED, "{path}");
    }
    let edit = app
        .client
        .put(app.url(&format!("/api/v1/kb/comments/{root_id}")))
        .bearer_auth(&contact_token)
        .json(&serde_json::json!({ "body": "hi" }))
        .send()
        .await
        .expect("send contact edit");
    assert_eq!(edit.status(), reqwest::StatusCode::UNAUTHORIZED);
    let del = app
        .client
        .delete(app.url(&format!("/api/v1/kb/comments/{root_id}")))
        .bearer_auth(&contact_token)
        .send()
        .await
        .expect("send contact delete");
    assert_eq!(del.status(), reqwest::StatusCode::UNAUTHORIZED);
}
