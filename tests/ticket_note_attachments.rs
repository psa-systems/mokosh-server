//! PMS-483: integration tests for the ticket-note attachment surface.
//!
//! Pins:
//!   - Agent: upload a small file to a note, list, download, delete.
//!   - Server enforces ATTACHMENT_MAX_BYTES; oversize bodies 413.
//!
//! The two portal cases (a same-company contact uploading to a note and
//! an agent downloading it; a sibling-company contact 404ing on the same
//! paths; a portal delete not reading the blob) went with the
//! `/portal/tickets/{id}/notes/{note}/attachments` routes PMS-1025
//! removed. The contact plane attaches at the ticket level only
//! (`POST /tickets/{id}/attachments`, `portal_attach_file`, covered in
//! `tests/portal_expanded_caps.rs`); the note-level surface is recorded
//! on PMS-1064 as coverage the cut removed.
//!   - PMS-783: a download is cacheable and revalidates to 304. The companion
//!     pin that the download STREAMS rather than buffering lives in
//!     `tests/attachment_download_streaming.rs`: its allocation probe is
//!     process-global and cannot share a binary with other cases (PMS-822).

mod common;

use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// A storage root private to this run, plus a tight 1 KiB cap. Blob filenames
/// are unique uuids so the cases in this binary, which run concurrently, do not
/// collide inside the shared root.
fn install_test_attachment_env() {
    common::storage_root();
    std::env::set_var("ATTACHMENT_MAX_BYTES", "1024");
}

#[sqlx::test]
async fn agent_upload_list_download_delete(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let part = Part::bytes(b"hello agent".to_vec())
        .file_name("hello.txt")
        .mime_str("text/plain")
        .expect("mime");
    let form = Form::new().part("file", part);
    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await
        .expect("upload");
    assert!(
        resp.status().is_success(),
        "upload status: {}",
        resp.status()
    );
    let row: Value = resp.json().await.expect("upload json");
    assert_eq!(row["file_name"], "hello.txt");
    assert_eq!(row["file_size"], 11);
    assert_eq!(row["mime_type"], "text/plain");
    assert!(row["uploaded_by_id"].is_string());
    assert!(row["created_by_contact_id"].is_null());
    let attachment_id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();

    let list_resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list");
    assert!(list_resp.status().is_success());
    let listed: Value = list_resp.json().await.expect("list json");
    assert_eq!(listed.as_array().unwrap().len(), 1);

    let dl = app
        .client
        .get(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("download");
    assert!(dl.status().is_success());
    assert_eq!(dl.bytes().await.unwrap().as_ref(), b"hello agent");

    let del = app
        .client
        .delete(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status().as_u16(), 204);
}

#[sqlx::test]
async fn oversize_upload_returns_413(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    // 2 KiB > 1 KiB cap configured by install_test_attachment_env.
    let oversize = vec![b'x'; 2048];
    let form = Form::new().part(
        "file",
        Part::bytes(oversize)
            .file_name("big.bin")
            .mime_str("application/octet-stream")
            .unwrap(),
    );
    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await
        .expect("oversize upload");
    assert_eq!(
        resp.status().as_u16(),
        413,
        "oversize must 413; got {}",
        resp.status()
    );
}

/// PMS-783 F6: the bytes behind one attachment URL never change, so a repeat
/// view must cost a conditional request, not a re-download.
#[sqlx::test]
async fn a_download_is_cacheable_and_revalidates_to_304(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let body = b"cache me".to_vec();
    let form = Form::new().part(
        "file",
        Part::bytes(body.clone())
            .file_name("cache.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let row: Value = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await
        .expect("upload")
        .json()
        .await
        .expect("upload json");
    let attachment_id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();
    let url = app.url(&format!(
        "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
    ));

    let first = app
        .client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .expect("first download");
    assert!(first.status().is_success());
    assert_eq!(
        first.headers()["cache-control"],
        "private, max-age=31536000, immutable",
        "private because the route is authenticated and company-scoped"
    );
    let etag = first.headers()["etag"].to_str().unwrap().to_string();
    assert_eq!(etag, format!("\"{attachment_id}-{}\"", body.len()));
    assert_eq!(
        first.headers()["content-length"],
        body.len().to_string(),
        "a streamed body still declares its length"
    );
    assert_eq!(first.bytes().await.unwrap().as_ref(), &body[..]);

    // Both the strong and the weak form of the validator revalidate: RFC 9110
    // compares If-None-Match weakly.
    for candidate in [etag.clone(), format!("W/{etag}")] {
        let repeat = app
            .client
            .get(&url)
            .bearer_auth(&token)
            .header("if-none-match", &candidate)
            .send()
            .await
            .expect("conditional download");
        assert_eq!(
            repeat.status().as_u16(),
            304,
            "if-none-match {candidate} should revalidate"
        );
        assert!(
            repeat.bytes().await.unwrap().is_empty(),
            "a 304 must not carry the blob"
        );
    }

    // A stale validator still gets the bytes.
    let changed = app
        .client
        .get(&url)
        .bearer_auth(&token)
        .header("if-none-match", "\"stale\"")
        .send()
        .await
        .expect("stale conditional download");
    assert!(changed.status().is_success());
    assert_eq!(changed.bytes().await.unwrap().as_ref(), &body[..]);
}
