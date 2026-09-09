//! The live tenant logo is addressed by its tenant, and the files that were
//! written before that are walked over to it.
//!
//! The interesting cases are all about a deployment that already has a logo on
//! disk at the shared `tenant-logos/{tenant}.{ext}` path. Each test below
//! builds that state the honest way - upload through the real route, then put
//! the file back where the old code would have left it - so the fixtures
//! cannot drift from what the store actually writes.
//!
//! This is `tests/kb_attachment_move.rs` for the other kind, deliberately: the
//! two movers are the same shape, and a difference between these files is a
//! difference worth seeing.

mod common;

use std::path::PathBuf;

use mokosh_server::db::Database;
use mokosh_server::modules::tenants::TenantLogoMover;
use reqwest::StatusCode;
use sqlx::PgPool;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// Serialises the tests in this binary, and it is not optional.
///
/// A logo's key is the TENANT plus a fixed name, so every case here addresses
/// the same two paths - unlike `kb_attachment_move.rs`, where each attachment
/// carries a fresh UUID and parallel cases cannot collide. `#[sqlx::test]`
/// gives each case its own DATABASE but they all share one process and one
/// storage root, so without this a test that stages the pre-move state renames
/// the file out from under a test asserting on a fresh upload. That is exactly
/// how this file first failed, on the one case that reads the path it did not
/// write.
static ONE_AT_A_TIME: Mutex<()> = Mutex::const_new(());

/// Take the lock AND start from a clean pair of paths: a case that leaves a
/// file behind must not decide the next one's assertions.
async fn exclusive() -> MutexGuard<'static, ()> {
    let guard = ONE_AT_A_TIME.lock().await;
    let _ = tokio::fs::remove_file(tenant_path()).await;
    let _ = tokio::fs::remove_file(legacy_path()).await;
    guard
}

const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

fn tenant_path() -> PathBuf {
    common::storage_root()
        .join(common::DEFAULT_TENANT_ID.to_string())
        .join("logo.png")
}

fn legacy_path() -> PathBuf {
    common::storage_root()
        .join("tenant-logos")
        .join(format!("{}.png", common::DEFAULT_TENANT_ID))
}

async fn upload_logo(app: &common::TestApp, token: &str) {
    let part = reqwest::multipart::Part::bytes(PNG.to_vec())
        .file_name("logo.png")
        .mime_str("image/png")
        .expect("mime");
    let resp = app
        .client
        .put(app.url("/api/v1/tenants/current/logo"))
        .bearer_auth(token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("upload logo");
    assert_eq!(resp.status(), StatusCode::OK, "logo upload");
}

/// Put an already-uploaded logo back where the pre-move code would have written
/// it, file and ledger row both, so the mover has something real to find.
async fn pretend_it_predates_the_move(pool: &PgPool) {
    let legacy = legacy_path();
    tokio::fs::create_dir_all(legacy.parent().expect("a parent"))
        .await
        .expect("legacy dir");
    tokio::fs::rename(tenant_path(), &legacy)
        .await
        .expect("move the file back");
    sqlx::query("UPDATE files SET storage_path = $1 WHERE id = $2")
        .bind(format!("tenant-logos/{}.png", common::DEFAULT_TENANT_ID))
        .bind(common::DEFAULT_TENANT_ID)
        .execute(pool)
        .await
        .expect("point the ledger at the old path");
}

async fn ledger_path(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar(
        "SELECT storage_path FROM files WHERE id = $1 AND entity_type = 'tenant_logo'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_optional(pool)
    .await
    .expect("read the ledger")
}

async fn fetch_public(app: &common::TestApp) -> (u16, Vec<u8>) {
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/public/tenants/{}/logo",
            common::DEFAULT_TENANT_ID
        )))
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
    common::storage_root();
    let _guard = exclusive().await;
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token).await;

    assert!(
        tenant_path().exists(),
        "a fresh logo belongs at {{tenant}}/logo.png"
    );
    assert!(
        !legacy_path().exists(),
        "nothing should be written to the shared directory any more"
    );
    assert_eq!(
        ledger_path(&pool).await.as_deref(),
        Some(format!("{}/logo.png", common::DEFAULT_TENANT_ID).as_str()),
        "the ledger records where the file actually is"
    );
}

/// The read falls back while the file is still at the old path, so a logo does
/// not vanish from a client's portal and emails between the deploy and the
/// first tick of the mover.
#[sqlx::test]
async fn a_logo_written_under_the_old_layout_is_still_served(pool: PgPool) {
    common::storage_root();
    let _guard = exclusive().await;
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token).await;
    pretend_it_predates_the_move(&pool).await;

    let (status, bytes) = fetch_public(&app).await;
    assert_eq!(status, 200, "the fallback serves the pre-move file");
    assert_eq!(bytes, PNG, "and serves the right bytes");
}

#[sqlx::test]
async fn the_mover_carries_a_legacy_logo_under_its_tenant(pool: PgPool) {
    common::storage_root();
    let _guard = exclusive().await;
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token).await;
    pretend_it_predates_the_move(&pool).await;
    assert!(
        legacy_path().exists(),
        "fixture: the file is at the old path"
    );

    let outcome = TenantLogoMover::new(Database::from_pool(pool.clone()))
        .run_tick()
        .await
        .expect("a tick");

    assert_eq!(outcome.moved, 1, "the one logo moved");
    assert!(tenant_path().exists(), "the file is under its tenant now");
    assert!(!legacy_path().exists(), "and is not left behind");
    assert_eq!(
        ledger_path(&pool).await.as_deref(),
        Some(format!("{}/logo.png", common::DEFAULT_TENANT_ID).as_str()),
        "the ledger followed the file"
    );

    let (status, bytes) = fetch_public(&app).await;
    assert_eq!(status, 200);
    assert_eq!(bytes, PNG, "and it still serves the same bytes");
}

/// The set the sweep selects is the UNMOVED one, so a second pass costs a query
/// and does nothing. A mover that reconsidered every logo every hour would be a
/// permanent load with no end state.
#[sqlx::test]
async fn a_second_pass_has_nothing_to_do(pool: PgPool) {
    common::storage_root();
    let _guard = exclusive().await;
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token).await;
    pretend_it_predates_the_move(&pool).await;

    let mover = TenantLogoMover::new(Database::from_pool(pool.clone()));
    mover.run_tick().await.expect("first tick");
    let second = mover.run_tick().await.expect("second tick");

    assert_eq!(
        second,
        Default::default(),
        "a completed move leaves the sweep with no rows"
    );
}

/// A tick that moved the file and then failed before it could say so leaves a
/// ledger row naming the old path. The next tick has to correct the row without
/// touching the file, because the file is already where it belongs.
#[sqlx::test]
async fn a_stale_ledger_row_is_corrected_without_touching_the_file(pool: PgPool) {
    common::storage_root();
    let _guard = exclusive().await;
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token).await;
    // File stays at the tenant path; only the ledger says otherwise.
    sqlx::query("UPDATE files SET storage_path = $1 WHERE id = $2")
        .bind(format!("tenant-logos/{}.png", common::DEFAULT_TENANT_ID))
        .bind(common::DEFAULT_TENANT_ID)
        .execute(&pool)
        .await
        .expect("stale the ledger row");

    let outcome = TenantLogoMover::new(Database::from_pool(pool.clone()))
        .run_tick()
        .await
        .expect("a tick");

    assert_eq!(outcome.already_moved, 1, "nothing to carry");
    assert_eq!(outcome.moved, 0);
    assert!(tenant_path().exists(), "the file was not disturbed");
    assert_eq!(
        ledger_path(&pool).await.as_deref(),
        Some(format!("{}/logo.png", common::DEFAULT_TENANT_ID).as_str()),
        "the row was corrected"
    );
}

/// A tenant whose branding claims a logo whose bytes are at neither path is
/// left completely alone. Rewriting its ledger row would dress a missing file
/// up as a migrated one.
#[sqlx::test]
async fn a_tenant_with_no_file_is_left_alone(pool: PgPool) {
    common::storage_root();
    let _guard = exclusive().await;
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token).await;
    pretend_it_predates_the_move(&pool).await;
    tokio::fs::remove_file(legacy_path())
        .await
        .expect("delete the bytes, keep the branding and the row");

    let outcome = TenantLogoMover::new(Database::from_pool(pool.clone()))
        .run_tick()
        .await
        .expect("a tick");

    assert_eq!(outcome.missing, 1);
    assert_eq!(outcome.moved, 0);
    assert_eq!(
        ledger_path(&pool).await.as_deref(),
        Some(format!("tenant-logos/{}.png", common::DEFAULT_TENANT_ID).as_str()),
        "the row still names the path the file was last known at"
    );
}

/// Replacing a logo before the mover has run must clear the pre-move file too,
/// or the read fallback serves the OLD mark for a tenant that just changed it.
#[sqlx::test]
async fn replacing_a_logo_clears_the_pre_move_file(pool: PgPool) {
    common::storage_root();
    let _guard = exclusive().await;
    let (_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token).await;
    pretend_it_predates_the_move(&pool).await;

    upload_logo(&app, &token).await;

    assert!(
        tenant_path().exists(),
        "the replacement is under its tenant"
    );
    assert!(
        !legacy_path().exists(),
        "and the file it replaced is gone from the shared directory"
    );
}

/// The public route is still the only way in, and it still refuses a tenant id
/// that has no logo, identically to one that does not exist. The layout moved;
/// the PMS-941 bargain did not.
#[sqlx::test]
async fn a_tenant_without_a_logo_is_indistinguishable_from_an_unknown_one(pool: PgPool) {
    common::storage_root();
    let _guard = exclusive().await;
    let app = common::boot(pool.clone()).await;

    let (no_logo, _) = fetch_public(&app).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/public/tenants/{}/logo", Uuid::new_v4())))
        .send()
        .await
        .expect("unknown tenant");
    assert_eq!(no_logo, resp.status().as_u16());
}
