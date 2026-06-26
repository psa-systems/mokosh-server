//! PMS-450 AC3: integration test for inbound email attachments.
//!
//! Drives the real `POST /api/v1/email-intake` surface with a seeded
//! intake token + contact and asserts:
//!   - a create-path intake with an `attachments` array stores each
//!     blob in `ticket_attachments` against the new ticket (note_id
//!     NULL), attributed to the sender contact, and reports the count
//!     via `attachments_stored`;
//!   - a threading-path reply stores its attachment against the reply
//!     note (note_id = the new public note's id);
//!   - a part whose base64 fails to decode is skipped (best-effort)
//!     without failing the whole intake.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct AttachmentRow {
    note_id: Option<Uuid>,
    file_name: String,
    mime_type: String,
    file_size: i32,
    created_by_contact_id: Option<Uuid>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Per-suite attachment dir + a cap generous enough for the tiny test
/// blobs. Blob filenames on disk are unique uuids so parallel tests do
/// not collide.
fn install_test_attachment_env() {
    std::env::set_var("ATTACHMENT_DIR", "/tmp/mokosh-pms450-test");
    std::env::set_var("ATTACHMENT_MAX_BYTES", "1048576");
}

#[sqlx::test]
async fn email_intake_stores_attachments(pool: PgPool) {
    install_test_attachment_env();

    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    let contact_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contacts (id, tenant_id, first_name, last_name, email, company_id)
           VALUES ($1, $2, 'Dana', 'Attacher', 'dana@example.com', $3)"#,
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    let bearer = "pms450-attach-token";
    sqlx::query(
        r#"INSERT INTO tenant_intake_tokens (tenant_id, kind, token_hash, label)
           VALUES ($1, 'email_intake', $2, 'attachment test gateway')"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(sha256_hex(bearer.as_bytes()))
    .execute(&pool)
    .await
    .expect("seed intake token");

    let app = common::boot(pool.clone()).await;

    let payload = b"hello attachment world";
    let b64 = STANDARD.encode(payload);

    // Create path: one valid attachment plus one with a garbage base64
    // payload. Only the valid one is stored; the intake still succeeds.
    let original_message_id = "<pms450-attach-1@example.com>";
    let created: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": original_message_id,
            "from_email": "dana@example.com",
            "from_name": "Dana Attacher",
            "subject": "Screenshot attached",
            "body_text": "See the attached screenshot.",
            "attachments": [
                {
                    "file_name": "screenshot.png",
                    "mime_type": "image/png",
                    "content_base64": b64,
                },
                {
                    "file_name": "broken.bin",
                    "content_base64": "this is not base64!!!",
                }
            ],
        }))
        .send()
        .await
        .expect("create POST")
        .json()
        .await
        .expect("create body");
    assert_eq!(created["created"], true);
    assert_eq!(
        created["attachments_stored"], 1,
        "exactly one valid attachment stored; body={created:?}"
    );
    let ticket_id = created["ticket_id"]
        .as_str()
        .expect("ticket_id")
        .to_string();

    // The stored row: against the ticket (note_id NULL), attributed to
    // the sender contact, with the original filename + mime preserved.
    let rows: Vec<AttachmentRow> = sqlx::query_as(
        "SELECT note_id, file_name, mime_type, file_size, created_by_contact_id \
         FROM ticket_attachments \
         WHERE tenant_id = $1 AND ticket_id = $2::uuid",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&ticket_id)
    .fetch_all(&pool)
    .await
    .expect("attachment rows");
    assert_eq!(rows.len(), 1, "one attachment row on the created ticket");
    let row = &rows[0];
    assert_eq!(
        row.note_id, None,
        "create-path attachment has a NULL note_id"
    );
    assert_eq!(row.file_name, "screenshot.png");
    assert_eq!(row.mime_type, "image/png");
    assert_eq!(row.file_size as usize, payload.len());
    assert_eq!(
        row.created_by_contact_id,
        Some(contact_id),
        "attachment attributed to the sender contact"
    );

    // Threading path: a reply with an attachment stores it against the
    // newly-created public reply note (note_id IS NOT NULL).
    let reply: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<pms450-attach-reply@example.com>",
            "from_email": "dana@example.com",
            "subject": "Re: Screenshot attached",
            "body_text": "And here is a second file.",
            "references": [original_message_id],
            "attachments": [
                {
                    "file_name": "log.txt",
                    "mime_type": "text/plain",
                    "content_base64": STANDARD.encode(b"line one\nline two\n"),
                }
            ],
        }))
        .send()
        .await
        .expect("reply POST")
        .json()
        .await
        .expect("reply body");
    assert_eq!(reply["threaded"], true);
    assert_eq!(reply["comment_added"], true);
    assert_eq!(reply["attachments_stored"], 1);

    let reply_row: (String, Option<Uuid>) = sqlx::query_as(
        "SELECT file_name, note_id FROM ticket_attachments \
         WHERE tenant_id = $1 AND ticket_id = $2::uuid AND file_name = 'log.txt'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&ticket_id)
    .fetch_one(&pool)
    .await
    .expect("reply attachment row");
    assert!(
        reply_row.1.is_some(),
        "reply-path attachment hangs off the reply note"
    );

    // Two rows total now on the ticket (create blob + reply blob).
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ticket_attachments WHERE tenant_id = $1 AND ticket_id = $2::uuid",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&ticket_id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count.0, 2);
}
