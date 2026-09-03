//! PMS-957: a tenant's reported storage usage is a fact, not a zero.
//!
//! `TenantUsage.storage_bytes` sums `files`, and nothing ever wrote to `files`,
//! so the figure was a constant zero on every deployment however much a tenant
//! uploaded. These tests go through the real upload paths, because the bug was
//! precisely that a table had a reader and no writer.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89,
];

async fn usage_bytes(app: &common::TestApp, token: &str) -> i64 {
    let resp = app
        .client
        .get(app.url(&format!(
            "/api/v1/tenants/{}/usage",
            common::DEFAULT_TENANT_ID
        )))
        .bearer_auth(token)
        .send()
        .await
        .expect("send usage request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "usage should 200");
    let usage: serde_json::Value = resp.json().await.expect("usage JSON");
    usage["storage_bytes"].as_i64().expect("storage_bytes")
}

async fn ledger_rows(pool: &PgPool) -> Vec<(String, i64)> {
    sqlx::query_as(
        "SELECT entity_type, file_size FROM files WHERE tenant_id = $1 ORDER BY entity_type",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(pool)
    .await
    .expect("read ledger")
}

async fn upload_logo(app: &common::TestApp, token: &str, bytes: &[u8]) {
    let part = reqwest::multipart::Part::bytes(bytes.to_vec())
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
        .expect("send logo upload");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "logo upload");
}

/// The bug, from the other side: something is uploaded and the number moves.
#[sqlx::test]
async fn uploading_a_logo_moves_the_reported_usage(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    assert_eq!(
        usage_bytes(&app, &token).await,
        0,
        "nothing stored yet, so zero is correct here"
    );

    upload_logo(&app, &token, PNG).await;

    assert_eq!(
        usage_bytes(&app, &token).await,
        PNG.len() as i64,
        "the figure follows what is actually stored"
    );
    assert_eq!(
        ledger_rows(&pool).await,
        vec![("tenant_logo".to_string(), PNG.len() as i64)]
    );
}

/// A logo is the one object written to the same key over and over. Replacing it
/// must not add a row, or a tenant's usage climbs every time they change their
/// branding while only one file is on disk.
#[sqlx::test]
async fn replacing_a_logo_does_not_add_to_the_total(pool: PgPool) {
    let (_admin, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    upload_logo(&app, &token, PNG).await;
    let bigger: Vec<u8> = PNG
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0u8, 100))
        .collect();
    upload_logo(&app, &token, &bigger).await;

    let rows = ledger_rows(&pool).await;
    assert_eq!(rows.len(), 1, "one logo, one row: {rows:?}");
    assert_eq!(
        usage_bytes(&app, &token).await,
        bigger.len() as i64,
        "the row follows the bytes now on disk, not the sum of every upload"
    );
}

/// Deleting an attachment gives the space back. Without this the figure only
/// ever climbs, which is a different wrong number from the one being fixed.
#[sqlx::test]
async fn deleting_an_attachment_returns_its_bytes(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let part = reqwest::multipart::Part::bytes(PNG.to_vec())
        .file_name("shot.png")
        .mime_str("image/png")
        .expect("mime");
    let uploaded = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("send attachment upload");
    assert!(
        uploaded.status().is_success(),
        "upload should 2xx, got {}",
        uploaded.status()
    );
    let attachment: serde_json::Value = uploaded.json().await.expect("attachment JSON");
    let attachment_id = attachment["id"].as_str().expect("id").to_string();

    assert_eq!(usage_bytes(&app, &token).await, PNG.len() as i64);
    assert_eq!(
        ledger_rows(&pool).await,
        vec![("ticket_attachment".to_string(), PNG.len() as i64)],
        "recorded under the kind that stored it"
    );

    let deleted = app
        .client
        .delete(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send delete");
    assert!(deleted.status().is_success(), "got {}", deleted.status());

    assert_eq!(usage_bytes(&app, &token).await, 0);
    assert!(ledger_rows(&pool).await.is_empty());
}

/// The ledger row IS the attachment, under the same id, so the two cannot
/// drift apart and a size recorded twice is impossible by construction.
#[sqlx::test]
async fn a_ledger_row_carries_the_objects_own_id_and_a_relative_path(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;

    let part = reqwest::multipart::Part::bytes(PNG.to_vec())
        .file_name("shot.png")
        .mime_str("image/png")
        .expect("mime");
    let uploaded: serde_json::Value = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(reqwest::multipart::Form::new().part("file", part))
        .send()
        .await
        .expect("upload")
        .json()
        .await
        .expect("JSON");
    let attachment_id: Uuid = uploaded["id"].as_str().expect("id").parse().expect("uuid");

    let (id, path, name, uploader): (Uuid, String, String, Option<Uuid>) = sqlx::query_as(
        "SELECT id, storage_path, original_name, uploaded_by_id FROM files WHERE tenant_id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("ledger row");

    assert_eq!(id, attachment_id, "one object, one id");
    assert_eq!(
        path,
        format!("{}/{}", common::DEFAULT_TENANT_ID, attachment_id),
        "relative to the storage root, never absolute: the root is deployment \
         configuration and a row that hard-codes it goes stale when it moves"
    );
    assert_eq!(
        name, "shot.png",
        "the name the uploader gave, not the stored one"
    );
    assert_eq!(uploader, Some(admin_id));
}
