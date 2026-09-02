//! PMS-922: a KB draft is in-progress text, and is never a revision.
//!
//! The editor wants autosave. It cannot have it against `PUT /kb/articles/{id}`
//! because `update_article` snapshots a version on every call, so a timer-driven
//! save would append a revision per interval and bury the real edits among
//! near-identical autosaves. These tests pin that the draft endpoints do not do
//! that, and that a draft is per-person, tenant-scoped, and cannot outlive its
//! article.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Create an article via the API and return its id.
async fn create_article(app: &common::TestApp, token: &str, title: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(token)
        .json(&json!({
            "title": title,
            "slug": title.to_lowercase().replace(' ', "-"),
            "content": "Original body.",
            "visibility": "internal",
            "status": "draft",
        }))
        .send()
        .await
        .expect("create article");
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.expect("json");
    assert_eq!(status, 200, "create article: {body}");
    body["id"].as_str().expect("an id").to_string()
}

async fn put_draft(
    app: &common::TestApp,
    token: &str,
    article: &str,
    title: &str,
    content: &str,
) -> u16 {
    app.client
        .put(app.url(&format!("/api/v1/kb/articles/{article}/draft")))
        .bearer_auth(token)
        .json(&json!({ "title": title, "content": content }))
        .send()
        .await
        .expect("put draft")
        .status()
        .as_u16()
}

async fn get_draft(app: &common::TestApp, token: &str, article: &str) -> (u16, Value) {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article}/draft")))
        .bearer_auth(token)
        .send()
        .await
        .expect("get draft");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn version_count(pool: &PgPool, article: &str) -> i64 {
    let id: Uuid = article.parse().expect("uuid");
    sqlx::query_scalar("SELECT COUNT(*) FROM kb_article_versions WHERE article_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count versions")
}

/// AC1, and the whole reason this endpoint exists. Twenty autosaves add twenty
/// rows to `kb_article_versions` if drafts go through `update_article`; here
/// they must add none.
#[sqlx::test]
async fn autosaving_a_draft_never_writes_a_version(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;

    let baseline = version_count(&pool, &article).await;

    for i in 0..20 {
        let status = put_draft(&app, &token, &article, "Runbook", &format!("Draft {i}")).await;
        assert_eq!(status, 200, "draft {i} should save");
    }

    assert_eq!(
        version_count(&pool, &article).await,
        baseline,
        "an autosaving editor must not append a revision per interval; that is \
         exactly the failure this endpoint exists to avoid"
    );
}

/// And the draft is readable, so autosave is recoverable rather than just
/// writes into a table nobody reads.
#[sqlx::test]
async fn a_draft_reads_back_and_reports_when_it_was_written(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;

    assert_eq!(
        get_draft(&app, &token, &article).await.0,
        404,
        "no draft yet reads as absent, not as an empty one"
    );

    put_draft(&app, &token, &article, "Runbook", "Half-written.").await;
    let (status, body) = get_draft(&app, &token, &article).await;
    assert_eq!(status, 200);
    assert_eq!(body["content"], "Half-written.");
    assert!(
        body["updated_at"].is_string(),
        "the client compares this against the article's own updated_at to decide \
         whether the draft is newer: {body}"
    );
}

/// The upsert replaces rather than accumulating, or the table grows per
/// keystroke and the "which draft is current" question comes back.
#[sqlx::test]
async fn saving_a_draft_twice_keeps_one_row(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;

    put_draft(&app, &token, &article, "Runbook", "First.").await;
    put_draft(&app, &token, &article, "Runbook", "Second.").await;

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kb_article_drafts")
        .fetch_one(&pool)
        .await
        .expect("count drafts");
    assert_eq!(rows, 1, "one draft per person per article");

    let (_, body) = get_draft(&app, &token, &article).await;
    assert_eq!(body["content"], "Second.", "the latest wins");
}

/// AC2. Two people editing one article keep separate drafts. A shared row would
/// resolve the conflict by losing somebody's work.
#[sqlx::test]
async fn drafts_are_per_person(pool: PgPool) {
    let (_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "manager@example.test",
        "manager",
    )
    .await;

    let app = common::boot(pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;
    let other_token = common::login(&app, "manager@example.test", "test-password-12345").await;
    let article = create_article(&app, &admin_token, "Runbook").await;

    put_draft(&app, &admin_token, &article, "Runbook", "Admin's text.").await;
    put_draft(&app, &other_token, &article, "Runbook", "Manager's text.").await;

    let (_, mine) = get_draft(&app, &admin_token, &article).await;
    let (_, theirs) = get_draft(&app, &other_token, &article).await;
    assert_eq!(mine["content"], "Admin's text.");
    assert_eq!(
        theirs["content"], "Manager's text.",
        "one person's autosave must not overwrite another's in-progress text"
    );
}

/// AC4. A real save supersedes the author's own draft, and only theirs.
#[sqlx::test]
async fn saving_the_article_clears_only_the_savers_draft(pool: PgPool) {
    let (_id, admin_email, admin_password) = common::seed_admin(&pool).await;
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "manager@example.test",
        "manager",
    )
    .await;

    let app = common::boot(pool).await;
    let admin_token = common::login(&app, &admin_email, &admin_password).await;
    let other_token = common::login(&app, "manager@example.test", "test-password-12345").await;
    let article = create_article(&app, &admin_token, "Runbook").await;

    put_draft(&app, &admin_token, &article, "Runbook", "Admin's text.").await;
    put_draft(&app, &other_token, &article, "Runbook", "Manager's text.").await;

    let resp = app
        .client
        .put(app.url(&format!("/api/v1/kb/articles/{article}")))
        .bearer_auth(&admin_token)
        .json(&json!({ "content": "Saved for real." }))
        .send()
        .await
        .expect("save article");
    assert_eq!(resp.status().as_u16(), 200);

    assert_eq!(
        get_draft(&app, &admin_token, &article).await.0,
        404,
        "the saver's draft is superseded by the save"
    );
    let (status, theirs) = get_draft(&app, &other_token, &article).await;
    assert_eq!(
        status, 200,
        "but somebody else's in-progress text is not resolved by another person \
         pressing Save"
    );
    assert_eq!(theirs["content"], "Manager's text.");
}

/// Discarding is idempotent: the caller's intent is satisfied whether or not
/// there was a draft to remove.
#[sqlx::test]
async fn discarding_a_draft_is_idempotent(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;
    put_draft(&app, &token, &article, "Runbook", "Text.").await;

    for round in 0..2 {
        let status = app
            .client
            .delete(app.url(&format!("/api/v1/kb/articles/{article}/draft")))
            .bearer_auth(&token)
            .send()
            .await
            .expect("delete draft")
            .status()
            .as_u16();
        assert_eq!(status, 204, "round {round}");
    }
    assert_eq!(get_draft(&app, &token, &article).await.0, 404);
}

/// AC5. A draft cannot outlive its article.
#[sqlx::test]
async fn deleting_the_article_takes_its_drafts(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;
    put_draft(&app, &token, &article, "Runbook", "Text.").await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/kb/articles/{article}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete article");
    assert!(resp.status().is_success(), "{}", resp.status());

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kb_article_drafts")
        .fetch_one(&pool)
        .await
        .expect("count drafts");
    assert_eq!(rows, 0, "the FK cascade takes the draft with the article");
}

/// AC7. A draft is not a side door into an article in another tenant.
#[sqlx::test]
async fn a_draft_cannot_reach_another_tenants_article(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    // A manager in a DIFFERENT tenant. `seed_tenant_with_admin` supplies the
    // tenant row; the editor is seeded with `seed_user` so it carries the same
    // known password every other test in this file logs in with.
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&pool, "other-msp").await;
    common::seed_user(&pool, other_tenant, "outsider@other.test", "manager").await;

    let app = common::boot(pool).await;
    let mine = common::login(&app, &email, &password).await;
    // PMS-138: login binds the lookup to `(tenant_id, email)` and falls back to
    // the DEFAULT tenant when the client sends no hint, so signing in as
    // somebody outside it needs the hint the SPA's subdomain would supply.
    let theirs = {
        let resp = app
            .client
            .post(app.url("/api/v1/auth/login"))
            .json(&json!({
                "email": "outsider@other.test",
                "password": "test-password-12345",
                "tenant_id": other_tenant,
            }))
            .send()
            .await
            .expect("login in the other tenant");
        assert!(resp.status().is_success(), "login: {}", resp.status());
        let body: Value = resp.json().await.expect("json");
        body["access_token"].as_str().expect("a token").to_string()
    };

    let article = create_article(&app, &mine, "Runbook").await;

    let status = put_draft(&app, &theirs, &article, "Runbook", "Not mine.").await;
    assert_eq!(
        status, 404,
        "an article in another tenant is not found, so there is nothing to draft \
         against"
    );
    assert_eq!(get_draft(&app, &theirs, &article).await.0, 404);
}

/// AC3-adjacent: a draft is editing, so it needs the same authority the save
/// does. Otherwise it is a way for a reader to stash text against an article
/// they cannot change.
#[sqlx::test]
async fn a_technician_cannot_draft(pool: PgPool) {
    let (_id, email, password) = common::seed_admin(&pool).await;
    common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.test",
        "technician",
    )
    .await;

    let app = common::boot(pool).await;
    let admin = common::login(&app, &email, &password).await;
    let tech = common::login(&app, "tech@example.test", "test-password-12345").await;
    let article = create_article(&app, &admin, "Runbook").await;

    assert_eq!(
        put_draft(&app, &tech, &article, "Runbook", "Text.").await,
        403,
        "whoever can save can draft, and nobody else"
    );
}
