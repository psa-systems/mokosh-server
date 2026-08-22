//! PMS-483: integration tests for the ticket-note attachment surface.
//!
//! Pins:
//!   - Agent: upload a small file to a note, list, download, delete.
//!   - Portal: a same-company contact can upload to a note on their own
//!     ticket and an agent can download it; a sibling-company contact
//!     gets 404 on the same paths (cross-company access deny).
//!   - Server enforces ATTACHMENT_MAX_BYTES; oversize bodies 413.
//!   - PMS-783: a download is cacheable and revalidates to 304. The companion
//!     pin that the download STREAMS rather than buffering lives in
//!     `tests/attachment_download_streaming.rs`: its allocation probe is
//!     process-global and cannot share a binary with other cases (PMS-822).

mod common;

use std::path::PathBuf;

use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Shared per-suite attachment dir + tight 1 KiB cap. Blob filenames
/// are unique uuids so parallel tests do not collide.
fn install_test_attachment_env() -> PathBuf {
    let dir = PathBuf::from("/tmp/mokosh-pms483-test");
    std::env::set_var("ATTACHMENT_DIR", &dir);
    std::env::set_var("ATTACHMENT_MAX_BYTES", "1024");
    dir
}

/// Insert a uniquely-named company on the default tenant. The shared
/// `common::seed_company` helper hard-codes "Acme Co" and trips the
/// per-tenant `(tenant_id, lower(name))` unique index when called
/// twice in the same test, so the cross-company test rolls its own.
async fn seed_company_named(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(common::DEFAULT_TENANT_ID)
        .bind(name)
        .execute(pool)
        .await
        .expect("seed company");
    id
}

async fn seed_contact(pool: &PgPool, company_id: Uuid) -> (Uuid, String, String) {
    let id = Uuid::new_v4();
    let email = format!("portal-{id}@example.com");
    let password = "portal-password-12345".to_string();
    let password_hash =
        mokosh_server::utils::crypto::hash_password(&password).expect("hash portal password");
    // `portal_enabled` is on the companies table; the contacts flag is
    // `is_portal_user` (migrations/004_contacts.sql:81). PMS-483 follow-up
    // CI report: the previous seed referenced the wrong column name.
    sqlx::query(
        r#"INSERT INTO contacts
           (id, tenant_id, company_id, email, first_name, last_name, portal_password_hash, is_portal_user)
           VALUES ($1, $2, $3, $4, 'Port', 'Al', $5, true)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .bind(&email)
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("seed contact");
    (id, email, password)
}

async fn portal_login(app: &common::TestApp, email: &str, password: &str) -> String {
    // `PortalLoginRequest` requires `tenant_slug` because `contacts.email`
    // is only unique within a tenant (`src/modules/portal/models.rs`).
    // The default tenant seeded in migration 002 has slug "default".
    let resp = app
        .client
        .post(app.url("/api/v1/portal/auth/login"))
        .json(&serde_json::json!({
            "tenant_slug": "default",
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("portal login");
    assert!(
        resp.status().is_success(),
        "portal login failed: {}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("portal login json");
    body["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
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

/// PMS-783 F6: a portal delete checks one uuid column, so it must not read the
/// blob. Proven by deleting the file first: the ownership check has nothing to
/// read, and the delete still succeeds. The old `get` returned 500 here.
#[sqlx::test]
async fn a_portal_delete_does_not_read_the_blob(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, _admin_email, _admin_pw) = common::seed_admin(&pool).await;
    let company_id = seed_company_named(&pool, "Delete Co").await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let (_contact_id, contact_email, contact_pw) = seed_contact(&pool, company_id).await;
    let app = common::boot(pool.clone()).await;
    let portal_token = portal_login(&app, &contact_email, &contact_pw).await;

    let form = Form::new().part(
        "file",
        Part::bytes(b"delete me".to_vec())
            .file_name("delete-me.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let row: Value = app
        .client
        .post(app.url(&format!(
            "/api/v1/portal/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&portal_token)
        .multipart(form)
        .send()
        .await
        .expect("portal upload")
        .json()
        .await
        .expect("portal upload json");
    let attachment_id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();

    let storage_path: String =
        sqlx::query_scalar("SELECT storage_path FROM ticket_attachments WHERE id = $1")
            .bind(attachment_id)
            .fetch_one(&pool)
            .await
            .expect("storage path");
    tokio::fs::remove_file(&storage_path)
        .await
        .expect("remove blob");

    let del = app
        .client
        .delete(app.url(&format!(
            "/api/v1/portal/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&portal_token)
        .send()
        .await
        .expect("portal delete");
    assert_eq!(
        del.status().as_u16(),
        204,
        "the ownership check must read the row, not the blob"
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

#[sqlx::test]
async fn portal_upload_visible_to_agent_blocked_for_sibling(pool: PgPool) {
    install_test_attachment_env();
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company_a = seed_company_named(&pool, "Acme Alpha").await;
    let company_b = seed_company_named(&pool, "Beta Industries").await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_a).await;
    let (contact_a_id, contact_a_email, contact_a_pw) = seed_contact(&pool, company_a).await;
    let (_contact_b_id, contact_b_email, contact_b_pw) = seed_contact(&pool, company_b).await;
    let app = common::boot(pool.clone()).await;
    let agent_token = common::login(&app, &admin_email, &admin_pw).await;
    let portal_token_a = portal_login(&app, &contact_a_email, &contact_a_pw).await;
    let portal_token_b = portal_login(&app, &contact_b_email, &contact_b_pw).await;

    // Same-company contact uploads.
    let form = Form::new().part(
        "file",
        Part::bytes(b"hi from portal".to_vec())
            .file_name("from-portal.txt")
            .mime_str("text/plain")
            .unwrap(),
    );
    let up_resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/portal/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&portal_token_a)
        .multipart(form)
        .send()
        .await
        .expect("portal upload");
    assert!(
        up_resp.status().is_success(),
        "same-company portal upload should 2xx; got {}",
        up_resp.status()
    );
    let row: Value = up_resp.json().await.expect("portal upload json");
    assert!(row["uploaded_by_id"].is_null());
    assert_eq!(
        row["created_by_contact_id"].as_str().map(str::to_string),
        Some(contact_a_id.to_string())
    );
    let attachment_id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();

    // Agent download succeeds.
    let agent_dl = app
        .client
        .get(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&agent_token)
        .send()
        .await
        .expect("agent download portal upload");
    assert!(agent_dl.status().is_success());
    assert_eq!(agent_dl.bytes().await.unwrap().as_ref(), b"hi from portal");

    // Sibling-company contact gets 404 on the same paths.
    for path in [
        format!("/api/v1/portal/tickets/{ticket_id}/notes/{note_id}/attachments"),
        format!("/api/v1/portal/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"),
    ] {
        let resp = app
            .client
            .get(app.url(&path))
            .bearer_auth(&portal_token_b)
            .send()
            .await
            .expect("cross-company");
        assert_eq!(
            resp.status().as_u16(),
            404,
            "cross-company {path} must 404; got {}",
            resp.status()
        );
    }
}
