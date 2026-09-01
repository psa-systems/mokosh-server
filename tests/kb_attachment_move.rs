//! PMS-960: a KB attachment is addressed by its tenant, and the files that were
//! written before that are walked over to it.
//!
//! The interesting cases are all about a deployment that already has images on
//! disk at the flat `kb-articles/{id}` path. Each test below builds that state
//! the honest way - upload through the real route, then put the file back where
//! the old code would have left it - so the fixtures cannot drift from what the
//! store actually writes.

mod common;

use std::path::PathBuf;

use mokosh_server::db::Database;
use mokosh_server::modules::knowledge_base::KbAttachmentMover;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const ROOT: &str = "/tmp/mokosh-pms960-test";

/// Set before `common::boot` and before the mover is built: both read
/// `ATTACHMENT_DIR` once, at construction.
fn install_test_attachment_env() {
    std::env::set_var("ATTACHMENT_DIR", ROOT);
}

const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

fn tenant_path(id: Uuid) -> PathBuf {
    PathBuf::from(ROOT)
        .join(common::DEFAULT_TENANT_ID.to_string())
        .join("kb-articles")
        .join(id.to_string())
}

fn legacy_path(id: Uuid) -> PathBuf {
    PathBuf::from(ROOT).join("kb-articles").join(id.to_string())
}

async fn create_article(app: &common::TestApp, token: &str) -> String {
    let slug = format!("runbook-{}", Uuid::new_v4());
    let resp = app
        .client
        .post(app.url("/api/v1/kb/articles"))
        .bearer_auth(token)
        .json(&json!({
            "title": "Runbook",
            "slug": slug,
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

async fn upload(app: &common::TestApp, token: &str, article: &str) -> Uuid {
    let part = reqwest::multipart::Part::bytes(PNG.to_vec())
        .file_name("shot.png".to_string())
        .mime_str("image/png")
        .expect("mime");
    let resp = app
        .client
        .post(app.url(&format!("/api/v1/kb/articles/{article}/attachments")))
        .bearer_auth(token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("upload");
    assert_eq!(resp.status().as_u16(), 200, "upload should succeed");
    let body: Value = resp.json().await.expect("json");
    body["id"].as_str().expect("an id").parse().expect("a uuid")
}

/// Put an already-uploaded attachment back where the pre-PMS-960 code would
/// have written it, file and ledger row both, so the mover has something real
/// to find.
async fn pretend_it_predates_the_move(pool: &PgPool, id: Uuid) {
    let legacy = legacy_path(id);
    tokio::fs::create_dir_all(legacy.parent().expect("a parent"))
        .await
        .expect("legacy dir");
    tokio::fs::rename(tenant_path(id), &legacy)
        .await
        .expect("move the file back");
    sqlx::query("UPDATE files SET storage_path = $1 WHERE id = $2")
        .bind(format!("kb-articles/{id}"))
        .bind(id)
        .execute(pool)
        .await
        .expect("point the ledger at the old path");
}

async fn ledger_path(pool: &PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT storage_path FROM files WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("read the ledger")
}

async fn fetch_public(app: &common::TestApp, id: Uuid) -> (u16, Vec<u8>) {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/public/kb/attachments/{id}")))
        .send()
        .await
        .expect("public fetch");
    let status = resp.status().as_u16();
    (status, resp.bytes().await.expect("bytes").to_vec())
}

/// A new upload goes straight to the tenant path. This is the layout change
/// itself, seen from the outside.
#[sqlx::test]
async fn a_fresh_upload_lands_under_its_tenant(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token).await;

    let id = upload(&app, &token, &article).await;

    assert!(
        tenant_path(id).exists(),
        "an upload is stored under its tenant, like every other object"
    );
    assert!(
        !legacy_path(id).exists(),
        "and never at the flat path again"
    );
    assert_eq!(
        ledger_path(&pool, id).await.as_deref(),
        Some(format!("{}/kb-articles/{id}", common::DEFAULT_TENANT_ID).as_str()),
        "the ledger records where it actually is"
    );
}

/// The requirement that makes the layout change safe to ship: an image uploaded
/// before this release is still served, before anything has moved it.
#[sqlx::test]
async fn a_file_written_under_the_old_layout_is_still_served(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token).await;
    let id = upload(&app, &token, &article).await;
    pretend_it_predates_the_move(&pool, id).await;

    let (status, bytes) = fetch_public(&app, id).await;

    assert_eq!(
        status, 200,
        "the fallback is what keeps this article intact"
    );
    assert_eq!(bytes, PNG);
}

/// And then the mover carries it over, without the article noticing.
#[sqlx::test]
async fn the_mover_carries_a_legacy_file_under_its_tenant(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token).await;
    let id = upload(&app, &token, &article).await;
    pretend_it_predates_the_move(&pool, id).await;

    let mover = KbAttachmentMover::new(Database::from_pool(pool.clone()));
    let outcome = mover.run_tick().await.expect("a pass");

    assert_eq!(outcome.moved, 1, "one file walked over: {outcome:?}");
    assert!(tenant_path(id).exists(), "it is under its tenant now");
    assert!(!legacy_path(id).exists(), "and gone from the flat path");
    assert_eq!(
        ledger_path(&pool, id).await.as_deref(),
        Some(format!("{}/kb-articles/{id}", common::DEFAULT_TENANT_ID).as_str()),
        "the ledger follows the file"
    );

    let (status, bytes) = fetch_public(&app, id).await;
    assert_eq!(status, 200, "the article is unchanged from a reader's side");
    assert_eq!(bytes, PNG);
}

/// A second pass finds nothing, which is the property that lets this run every
/// hour for the life of the deployment.
#[sqlx::test]
async fn a_second_pass_has_nothing_to_do(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token).await;
    let id = upload(&app, &token, &article).await;
    pretend_it_predates_the_move(&pool, id).await;

    let mover = KbAttachmentMover::new(Database::from_pool(pool.clone()));
    mover.run_tick().await.expect("first pass");
    let second = mover.run_tick().await.expect("second pass");

    assert_eq!(second.moved, 0);
    assert_eq!(second.already_moved, 0);
    assert_eq!(second.missing, 0, "a moved row is not selected again");
}

/// A moved file whose ledger row never caught up is corrected rather than
/// moved, which is the half-failure the ordering can leave behind.
#[sqlx::test]
async fn a_stale_ledger_row_is_corrected_without_touching_the_file(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token).await;
    let id = upload(&app, &token, &article).await;
    // The file is where it belongs; only the row lies.
    sqlx::query("UPDATE files SET storage_path = $1 WHERE id = $2")
        .bind(format!("kb-articles/{id}"))
        .bind(id)
        .execute(&pool)
        .await
        .expect("stale the row");

    let mover = KbAttachmentMover::new(Database::from_pool(pool.clone()));
    let outcome = mover.run_tick().await.expect("a pass");

    assert_eq!(outcome.already_moved, 1, "seen as done: {outcome:?}");
    assert_eq!(outcome.moved, 0);
    assert!(tenant_path(id).exists());
    assert_eq!(
        ledger_path(&pool, id).await.as_deref(),
        Some(format!("{}/kb-articles/{id}", common::DEFAULT_TENANT_ID).as_str())
    );
}

/// An attachment whose bytes are at neither path is left completely alone,
/// ledger row included. Rewriting that row would dress a missing file up as a
/// migrated one.
#[sqlx::test]
async fn an_attachment_with_no_file_is_left_alone(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token).await;
    let id = upload(&app, &token, &article).await;
    pretend_it_predates_the_move(&pool, id).await;
    tokio::fs::remove_file(legacy_path(id))
        .await
        .expect("lose the file");

    let mover = KbAttachmentMover::new(Database::from_pool(pool.clone()));
    let outcome = mover.run_tick().await.expect("a pass");

    assert_eq!(outcome.missing, 1, "counted, not hidden: {outcome:?}");
    assert_eq!(outcome.moved, 0);
    assert_eq!(
        ledger_path(&pool, id).await.as_deref(),
        Some(format!("kb-articles/{id}").as_str()),
        "the row still says where the file was, because it is not anywhere else"
    );
}

/// Deleting an attachment removes the bytes wherever they are, so an image the
/// mover never reached does not survive its own row.
#[sqlx::test]
async fn deleting_an_unmoved_attachment_removes_the_legacy_file(pool: PgPool) {
    install_test_attachment_env();
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let article = create_article(&app, &token).await;
    let id = upload(&app, &token, &article).await;
    pretend_it_predates_the_move(&pool, id).await;

    let resp = app
        .client
        .delete(app.url(&format!("/api/v1/kb/articles/{article}/attachments/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status().as_u16(), 204);

    assert!(
        !legacy_path(id).exists(),
        "a blob nothing can name still costs the volume"
    );
    assert_eq!(fetch_public(&app, id).await.0, 404);
}
