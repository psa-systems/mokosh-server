//! PMS-1233 regression: the branding asset route must raise
//! `axum::extract::DefaultBodyLimit` to match its per-scope cap, or axum's
//! undocumented 2 MiB framework default pre-empts the upload with a generic
//! 400 before `oversized_upload_error` ever runs.
//!
//! The tenant background cap defaults to exactly 2 MiB
//! (`DEFAULT_BACKGROUND_MAX_BYTES` in `src/modules/branding/assets.rs`), which
//! is the sharpest case in the issue: multipart framing (the boundary
//! delimiter and each part's own headers) rides on top of the file bytes
//! inside the body axum's `DefaultBodyLimit` measures, so a limit set to
//! exactly 2 MiB would refuse an AT-CAP file the instant its framing is
//! counted. No env override here: the default cap is the value the issue
//! names, so the first test below is the literal acceptance criterion.

mod common;

use mokosh_test::mokosh_test;
use sqlx::PgPool;

fn install_test_env() {
    common::storage_root();
}

async fn upload_background(app: &common::TestApp, token: &str, size: usize) -> reqwest::Response {
    let part = reqwest::multipart::Part::bytes(vec![0u8; size])
        .file_name("background.png")
        .mime_str("image/png")
        .expect("mime");
    app.client
        .put(app.url("/api/v1/tenants/current/branding/background"))
        .bearer_auth(token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("send upload")
}

#[mokosh_test]
async fn a_background_upload_at_exactly_the_cap_is_accepted(pool: PgPool) {
    install_test_env();
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let resp = upload_background(&app, &token, 2 * 1024 * 1024).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a file at exactly the 2 MiB background cap must be accepted, not \
         refused because multipart framing pushed the body over axum's own \
         2 MiB stock default"
    );
}

#[mokosh_test]
async fn a_background_upload_over_the_cap_is_refused_with_413(pool: PgPool) {
    install_test_env();
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    // Over the 2 MiB cap but within the `body_limit_bytes` margin axum's own
    // `DefaultBodyLimit` was raised to, so the request reaches the handler's
    // own cap check instead of axum's multipart-read rejection.
    let resp = upload_background(&app, &token, 2 * 1024 * 1024 + 32 * 1024).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "a file over the background cap must get the app's own 413, not a \
         generic 400 from axum's multipart body limit"
    );
}
