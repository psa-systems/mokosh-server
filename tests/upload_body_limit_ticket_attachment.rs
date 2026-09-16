//! PMS-1233 regression: a ticket note attachment route must raise
//! `axum::extract::DefaultBodyLimit` to match its own configured cap, or
//! axum's undocumented 2 MiB framework default pre-empts every upload above
//! that size with a generic 400 before `oversized_upload_error` ever runs.
//!
//! `ATTACHMENT_MAX_BYTES` is overridden to 3 MiB so the two payloads below
//! (2.5 MiB, comfortably over axum's 2 MiB stock default; a little over 3 MiB,
//! over the configured cap but still within the 64 KiB margin
//! `body_limit_bytes` raises axum's own `DefaultBodyLimit` by) stay small
//! while still exercising both sides of the fix. A file oversized enough to
//! also exceed that raised `DefaultBodyLimit` would hit axum's own rejection
//! instead of the app's, which is not what this test is pinning. One process
//! per test file, so the override cannot race a sibling test file using a
//! different value.

mod common;

use sqlx::PgPool;

fn install_test_env() {
    common::storage_root();
    std::env::set_var("ATTACHMENT_MAX_BYTES", "3145728"); // 3 MiB
}

#[sqlx::test]
async fn an_upload_between_axums_default_and_the_configured_cap_is_accepted(pool: PgPool) {
    install_test_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let part = reqwest::multipart::Part::bytes(vec![0u8; 2_500_000])
        .file_name("attachment.bin")
        .mime_str("application/octet-stream")
        .expect("mime");
    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("send upload");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a 2.5 MiB file is under the 3 MiB configured cap and must be accepted, \
         not refused by axum's own 2 MiB stock default"
    );
}

#[sqlx::test]
async fn an_upload_over_the_configured_cap_is_refused_with_413(pool: PgPool) {
    install_test_env();
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let part = reqwest::multipart::Part::bytes(vec![0u8; 3_145_728 + 32 * 1024])
        .file_name("attachment.bin")
        .mime_str("application/octet-stream")
        .expect("mime");
    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("send upload");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "a file over the configured cap must get the app's own 413, not a \
         generic 400 from axum's multipart body limit"
    );
}
