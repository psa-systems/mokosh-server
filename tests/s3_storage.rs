//! PMS-958: the S3 provider against a real object store.
//!
//! Runs when `S3_ENDPOINT` is set and skips, saying so, when it is not. CI
//! starts a MinIO in the job and sets the `S3_*` variables for the whole run;
//! locally `just dev-s3` starts one in the dev stack and fills them into
//! `.env`. There is no second set of names for tests: the suite reads the
//! production variables, so what it proves is the configuration an operator
//! would write.
//!
//! `STORAGE_BACKEND=s3` is set by THIS process only, so every other suite in
//! the same CI run keeps exercising the local provider. It has to be set before
//! the first `boot` in this binary, because the store is process-wide and built
//! on first use.
//!
//! Every case here talks to one shared bucket. Keys carry a fresh tenant id per
//! case, so concurrent cases cannot collide, which is the same property the
//! local suites lean on with one root per binary.

mod common;

use std::sync::OnceLock;

use mokosh_server::storage::s3::S3Provider;
use mokosh_server::storage::{ObjectKey, ObjectProvider};
use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sqlx::PgPool;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

/// The store under test, or `None` with a skip line when no endpoint is
/// configured. Also flips this process onto the S3 provider, once, before
/// anything can build the shared store.
async fn s3() -> Option<S3Provider> {
    static SELECTED: OnceLock<bool> = OnceLock::new();
    let configured = *SELECTED.get_or_init(|| {
        let endpoint = std::env::var("S3_ENDPOINT").unwrap_or_default();
        if endpoint.trim().is_empty() {
            eprintln!("s3_storage: skipped, S3_ENDPOINT is not set");
            return false;
        }
        std::env::set_var("STORAGE_BACKEND", "s3");
        true
    });
    if !configured {
        return None;
    }
    let store = S3Provider::from_env().expect("S3 configuration");
    store.ensure_bucket().await.expect("create the test bucket");
    Some(store)
}

async fn read_all(mut reader: mokosh_server::storage::ObjectReader) -> Vec<u8> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.expect("read stream");
    out
}

/// Every operation on the trait, round-tripped through a real store.
#[tokio::test]
async fn every_operation_round_trips() {
    let Some(store) = s3().await else { return };
    let tenant = Uuid::new_v4();
    let id = Uuid::new_v4();
    let key = ObjectKey::ticket_attachment(tenant, id);
    let bytes: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();

    assert!(!store.exists(&key).await.unwrap());
    assert!(
        matches!(
            store.read(&key).await,
            Err(mokosh_server::utils::error::AppError::NotFound(_))
        ),
        "a missing object reads as NotFound, like the local provider"
    );

    store.put(&key, &bytes).await.expect("put");
    assert!(store.exists(&key).await.unwrap());
    assert_eq!(store.read(&key).await.unwrap(), bytes);
    assert_eq!(
        read_all(store.open(&key).await.unwrap()).await,
        bytes,
        "the streamed body is the whole object"
    );
    assert_eq!(
        store.location(&key).unwrap(),
        format!("s3://{}/{tenant}/{id}", store.config().bucket)
    );

    // Overwrite is a plain second put: the logo is written to one key per
    // tenant and replaced in place.
    store.put(&key, b"replaced").await.expect("overwrite");
    assert_eq!(store.read(&key).await.unwrap(), b"replaced");

    store.delete(&key).await.expect("delete");
    assert!(!store.exists(&key).await.unwrap());
    store
        .delete(&key)
        .await
        .expect("deleting what is already gone is not an error");
}

/// The PMS-960 mover's contract: a move carries the bytes and leaves nothing
/// behind, and moving something that is not there is an error rather than a
/// silent success that would mark an object migrated when nothing moved.
#[tokio::test]
async fn a_move_carries_the_bytes_and_leaves_nothing_behind() {
    let Some(store) = s3().await else { return };
    let tenant = Uuid::new_v4();
    let id = Uuid::new_v4();
    let legacy = ObjectKey::legacy_kb_attachment(tenant, id);
    let destination = ObjectKey::kb_attachment(tenant, id);

    assert!(
        store.rename(&legacy, &destination).await.is_err(),
        "moving a missing source must fail"
    );

    store.put(&legacy, b"image bytes").await.unwrap();
    store.rename(&legacy, &destination).await.expect("rename");
    assert_eq!(store.read(&destination).await.unwrap(), b"image bytes");
    assert!(!store.exists(&legacy).await.unwrap());

    store.delete(&destination).await.unwrap();
}

/// Tenant scoping, tested the way the local layout is: two tenants asking for
/// "their" object of the same kind and id land on two objects, and one
/// tenant's key cannot read the other's bytes.
#[tokio::test]
async fn two_tenants_cannot_reach_each_others_objects() {
    let Some(store) = s3().await else { return };
    let id = Uuid::new_v4();
    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    let digest = "5".repeat(64);

    for (a, b) in [
        (
            ObjectKey::ticket_attachment(mine, id),
            ObjectKey::ticket_attachment(theirs, id),
        ),
        (
            ObjectKey::tenant_logo(mine, "png"),
            ObjectKey::tenant_logo(theirs, "png"),
        ),
        (
            ObjectKey::kb_attachment(mine, id),
            ObjectKey::kb_attachment(theirs, id),
        ),
        (
            ObjectKey::financial_document(mine, id),
            ObjectKey::financial_document(theirs, id),
        ),
        (
            ObjectKey::branding_logo(mine, &digest),
            ObjectKey::branding_logo(theirs, &digest),
        ),
    ] {
        store.put(&a, b"mine").await.unwrap();
        assert!(
            !store.exists(&b).await.unwrap(),
            "{b:?} must not be reachable through {a:?}"
        );
        store.put(&b, b"theirs").await.unwrap();
        assert_eq!(store.read(&a).await.unwrap(), b"mine");
        assert_eq!(store.read(&b).await.unwrap(), b"theirs");
        store.delete(&a).await.unwrap();
        assert!(
            store.exists(&b).await.unwrap(),
            "deleting {a:?} must not touch {b:?}"
        );
        store.delete(&b).await.unwrap();
    }
}

/// Backend selection, end to end: with `STORAGE_BACKEND=s3` an upload through
/// the API lands in the bucket and NOT on the filesystem, and the download
/// streams it back from there.
#[sqlx::test]
async fn an_upload_through_the_api_lands_in_the_bucket_and_not_on_disk(pool: PgPool) {
    let Some(store) = s3().await else { return };
    std::env::set_var("ATTACHMENT_MAX_BYTES", "1048576");
    let (admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let (ticket_id, note_id) = common::seed_ticket_and_note(&pool, admin_id, company_id).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &admin_email, &admin_pw).await;

    let payload = b"bytes that must reach the bucket".to_vec();
    let part = Part::bytes(payload.clone())
        .file_name("hello.txt")
        .mime_str("text/plain")
        .expect("mime");
    let resp = app
        .client
        .post(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments"
        )))
        .bearer_auth(&token)
        .multipart(Form::new().part("file", part))
        .send()
        .await
        .expect("upload");
    assert!(
        resp.status().is_success(),
        "upload status: {}",
        resp.status()
    );
    let row: Value = resp.json().await.expect("upload json");
    let attachment_id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();

    // In the bucket, under the tenant, by id: the same key the local layout
    // would have used as a path.
    let key = ObjectKey::ticket_attachment(common::DEFAULT_TENANT_ID, attachment_id);
    assert_eq!(store.read(&key).await.expect("object in bucket"), payload);

    // And not on disk. The harness picked a private root for this binary;
    // nothing under it should exist for this tenant.
    let on_disk = common::storage_root()
        .join(common::DEFAULT_TENANT_ID.to_string())
        .join(attachment_id.to_string());
    assert!(
        !on_disk.exists(),
        "the local provider must not have been used: {on_disk:?} exists"
    );

    let dl = app
        .client
        .get(app.url(&format!(
            "/api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}"
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("download");
    assert!(dl.status().is_success(), "download status: {}", dl.status());
    assert_eq!(dl.bytes().await.unwrap().as_ref(), payload.as_slice());

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
    assert!(
        !store.exists(&key).await.unwrap(),
        "deleting the row deletes the object"
    );
}
