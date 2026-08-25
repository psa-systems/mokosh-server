//! PMS-923: images a KB article can embed, and the public URL an `<img>` can
//! actually fetch.
//!
//! The read path is unauthenticated by necessity: a browser fetches an embedded
//! image as `<img src="...">`, which carries no `Authorization` header, and the
//! SPA holds a bearer rather than a cookie. The attachment's v4 UUID is the only
//! credential. These tests pin what that does and does not permit.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Point the upload root somewhere writable, the way every other attachment
/// suite does. Without this the service writes under the deployed
/// `/data/attachments` default, which the host test environment cannot create.
///
/// Set before `common::boot`, because `KbAttachmentConfig::from_env` is read
/// when the router is built.
fn install_test_attachment_env() {
    std::env::set_var("ATTACHMENT_DIR", "/tmp/mokosh-pms923-test");
}

/// A one-pixel PNG, so the fixture is a real image of the allowed type.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

async fn create_article(app: &common::TestApp, token: &str, title: &str) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(token)
        .json(&json!({
            "title": title,
            "slug": title.to_lowercase().replace(' ', "-"),
            "content": "Body.",
            "visibility": "internal",
            "status": "draft",
        }))
        .send()
        .await
        .expect("create article");
    let body: Value = resp.json().await.expect("json");
    body["id"].as_str().expect("an id").to_string()
}

async fn upload(
    app: &common::TestApp,
    token: &str,
    article: &str,
    name: &str,
    mime: &str,
    bytes: Vec<u8>,
) -> (u16, Value) {
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(name.to_string())
        .mime_str(mime)
        .expect("mime");
    let form = reqwest::multipart::Form::new().part("file", part);
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/kb/articles/{article}/attachments")))
        .bearer_auth(token)
        .multipart(form)
        .send()
        .await
        .expect("upload");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The whole point: upload an image, then fetch it with no session at all,
/// which is what a browser rendering `<img>` does.
#[sqlx::test]
async fn an_uploaded_image_is_fetchable_without_a_session(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;

    let (status, body) = upload(
        &app,
        &token,
        &article,
        "shot.png",
        "image/png",
        PNG.to_vec(),
    )
    .await;
    assert_eq!(status, 200, "upload: {body}");
    let url = body["url"].as_str().expect("a url").to_string();
    assert!(
        url.starts_with("/api/v1/public/kb/attachments/"),
        "relative, so the SPA joins its own API base: {url}"
    );

    // No bearer. This is the request an `<img>` makes.
    let resp = app
        .client
        .get(app.url(&url))
        .send()
        .await
        .expect("public fetch");
    assert_eq!(resp.status().as_u16(), 200, "an <img> carries no header");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("image/png")
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "the bytes are user-supplied, so a browser must not sniff its way to \
         something scriptable"
    );
    assert_eq!(resp.bytes().await.expect("bytes").as_ref(), PNG);
}

/// AC2. SVG is script-capable and this route serves it from the API origin to
/// unauthenticated clients, so it is refused at upload, not at render.
#[sqlx::test]
async fn an_svg_is_refused(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;

    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
    let (status, body) = upload(
        &app,
        &token,
        &article,
        "x.svg",
        "image/svg+xml",
        svg.to_vec(),
    )
    .await;
    assert_eq!(status, 400, "an SVG must not be storable: {body}");
}

/// AC4. An unknown id and a deleted attachment answer identically, so the
/// public route is not an existence oracle for ids somebody is guessing at.
#[sqlx::test]
async fn an_unknown_and_a_deleted_attachment_are_indistinguishable(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;

    let (_, body) = upload(&app, &token, &article, "a.png", "image/png", PNG.to_vec()).await;
    let id = body["id"].as_str().expect("an id").to_string();

    let deleted = app
        .client
        .delete(app.url(&format!("/api/v1/kb/articles/{article}/attachments/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(deleted.status().as_u16(), 204);

    let gone = app
        .client
        .get(app.url(&format!("/api/v1/public/kb/attachments/{id}")))
        .send()
        .await
        .expect("fetch deleted");
    let never = app
        .client
        .get(app.url(&format!("/api/v1/public/kb/attachments/{}", Uuid::new_v4())))
        .send()
        .await
        .expect("fetch unknown");
    assert_eq!(gone.status().as_u16(), 404);
    assert_eq!(
        never.status().as_u16(),
        gone.status().as_u16(),
        "a deleted attachment and an id that never existed must not be \
         distinguishable"
    );
}

/// AC1. Upload is authenticated and tenant-scoped, even though the read is not.
#[sqlx::test]
async fn upload_needs_a_session_and_the_right_tenant(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&pool, "other-msp").await;
    common::seed_user(&pool, other_tenant, "outsider@other.test", "manager").await;

    let app = common::boot(pool).await;
    let mine = common::login(&app, &email, &password).await;
    let article = create_article(&app, &mine, "Runbook").await;

    // No session at all.
    let part = reqwest::multipart::Part::bytes(PNG.to_vec())
        .file_name("a.png")
        .mime_str("image/png")
        .expect("mime");
    let anon = app
        .client
        .post(app.url(&format!("/api/v1/kb/articles/{article}/attachments")))
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("anon upload");
    assert_eq!(
        anon.status().as_u16(),
        401,
        "the WRITE still needs a session"
    );

    // A session in another tenant. PMS-138 binds login to (tenant_id, email),
    // so signing in outside the default tenant needs the hint the SPA's
    // subdomain would supply.
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
            .expect("login elsewhere");
        assert!(resp.status().is_success());
        let body: Value = resp.json().await.expect("json");
        body["access_token"].as_str().expect("token").to_string()
    };
    let (status, _) = upload(&app, &theirs, &article, "a.png", "image/png", PNG.to_vec()).await;
    assert_eq!(
        status, 404,
        "an article in another tenant is not found, so there is nothing to \
         attach to"
    );
}

/// AC5. Deleting the article takes its attachments with it, so a published
/// article's images cannot outlive the article and keep serving.
#[sqlx::test]
async fn deleting_the_article_takes_its_attachments(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;
    upload(&app, &token, &article, "a.png", "image/png", PNG.to_vec()).await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/kb/articles/{article}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete article");
    assert!(resp.status().is_success());

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kb_article_attachments")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "the FK cascade takes the attachment rows");
}

/// A technician can read a published article but cannot attach to one, matching
/// the authority the article PUT requires.
#[sqlx::test]
async fn a_technician_cannot_upload(pool: PgPool) {
    install_test_attachment_env();
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

    let (status, _) = upload(&app, &tech, &article, "a.png", "image/png", PNG.to_vec()).await;
    assert_eq!(status, 403);
}

/// The listing lets the editor offer what is already uploaded instead of making
/// the author upload the same screenshot twice.
#[sqlx::test]
async fn an_articles_images_are_listable(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token, "Runbook").await;

    upload(&app, &token, &article, "one.png", "image/png", PNG.to_vec()).await;
    upload(&app, &token, &article, "two.png", "image/png", PNG.to_vec()).await;

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/kb/articles/{article}/attachments")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    let body: Value = resp.json().await.expect("json");
    let names: Vec<&str> = body
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|r| r["file_name"].as_str())
        .collect();
    assert_eq!(names.len(), 2, "{body}");
    assert!(
        names.contains(&"one.png") && names.contains(&"two.png"),
        "{body}"
    );
}
