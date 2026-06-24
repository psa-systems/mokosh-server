//! PMS-469 / PMS-450 phase-2 follow-ups: integration tests for
//! auto-create-contact, reply-as-comment, and the intake-log audit
//! surface.
//!
//! Three slices, one test each:
//!   - `auto_create_contact_under_fallback_company`: with the
//!     `email_intake/default_company_id` setting populated, an
//!     unknown-sender intake creates a contact under that company
//!     and then creates the ticket. With the setting absent, the
//!     same intake still 422s (Phase 1 posture preserved).
//!   - `reply_appends_public_comment`: a References-matching intake
//!     adds a `note_type='public'` row attributed (via
//!     `created_by_contact_id`) to the matched sender contact and
//!     the response carries `comment_added=true`.
//!   - `every_intake_writes_a_log_row`: any intake (success or
//!     failure) writes an `email_intake_log` row reachable via the
//!     admin GET endpoint; the row carries `ticket_id` for the
//!     happy path and `error` for the 422 path.

mod common;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

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

async fn seed_token(pool: &PgPool, bearer: &str) {
    sqlx::query(
        r#"INSERT INTO tenant_intake_tokens (tenant_id, kind, token_hash, label)
           VALUES ($1, 'email_intake', $2, 'phase-2 test gateway')"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(sha256_hex(bearer.as_bytes()))
    .execute(pool)
    .await
    .expect("seed intake token");
}

#[sqlx::test]
async fn auto_create_contact_under_fallback_company(pool: PgPool) {
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let fallback_company = common::seed_company(&pool).await;
    let bearer = "phase2-token-autocreate";
    seed_token(&pool, bearer).await;

    let app = common::boot(pool.clone()).await;

    // Without the setting, an unknown sender still 422s.
    let unknown_first = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<phase2-autocreate-pre@example.com>",
            "from_email": "newcomer@example.com",
            "subject": "Hi",
            "body_text": "no contact yet",
        }))
        .send()
        .await
        .expect("pre-setting POST");
    assert_eq!(unknown_first.status().as_u16(), 400);

    // Populate the fallback company setting.
    sqlx::query(
        r#"INSERT INTO tenant_settings (tenant_id, category, key, value)
           VALUES ($1, 'email_intake', 'default_company_id', to_jsonb($2::text))"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(fallback_company.to_string())
    .execute(&pool)
    .await
    .expect("seed fallback company setting");

    // Same unknown sender, this time the intake auto-creates the
    // contact under the fallback company AND creates the ticket.
    let resp: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<phase2-autocreate-post@example.com>",
            "from_email": "Newcomer@Example.com",
            "from_name": "New Comer",
            "subject": "Hi",
            "body_text": "now I'm auto-created",
        }))
        .send()
        .await
        .expect("post-setting POST")
        .json()
        .await
        .expect("post-setting body");
    assert_eq!(resp["created"], true);

    let (contact_id, company_id): (Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT id, company_id FROM contacts \
         WHERE tenant_id = $1 AND lower(email) = 'newcomer@example.com'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("contact row");
    assert_eq!(
        company_id,
        Some(fallback_company),
        "auto-created contact must point at the fallback company"
    );

    let ticket_contact: Option<Uuid> =
        sqlx::query_scalar("SELECT contact_id FROM tickets WHERE id = $1::uuid")
            .bind(resp["ticket_id"].as_str().expect("ticket_id"))
            .fetch_one(&pool)
            .await
            .expect("ticket contact");
    assert_eq!(
        ticket_contact,
        Some(contact_id),
        "ticket must reference the auto-created contact"
    );
}

#[sqlx::test]
async fn reply_appends_public_comment(pool: PgPool) {
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let bearer = "phase2-token-reply";
    seed_token(&pool, bearer).await;

    let contact_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contacts (id, tenant_id, first_name, last_name, email, company_id)
           VALUES ($1, $2, 'Bob', 'Replier', 'bob@example.com', $3)"#,
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    let app = common::boot(pool.clone()).await;

    let original_message_id = "<phase2-original@example.com>";
    let first: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": original_message_id,
            "from_email": "bob@example.com",
            "subject": "Original",
            "body_text": "Opening message",
        }))
        .send()
        .await
        .expect("original POST")
        .json()
        .await
        .expect("original body");
    let ticket_id = first["ticket_id"].as_str().expect("ticket_id").to_string();

    let reply: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<phase2-reply@example.com>",
            "from_email": "bob@example.com",
            "subject": "Re: Original",
            "body_text": "Following up.",
            "references": [original_message_id],
        }))
        .send()
        .await
        .expect("reply POST")
        .json()
        .await
        .expect("reply body");
    assert_eq!(reply["threaded"], true);
    assert_eq!(
        reply["comment_added"], true,
        "reply must append a public comment; body={reply:?}"
    );
    assert_eq!(reply["ticket_id"].as_str(), Some(ticket_id.as_str()));

    let notes: Vec<(String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT note_type, content, created_by_contact_id \
         FROM ticket_notes WHERE tenant_id = $1 AND ticket_id = $2::uuid \
         ORDER BY created_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(&ticket_id)
    .fetch_all(&pool)
    .await
    .expect("notes");
    let public = notes
        .iter()
        .find(|(t, _, _)| t == "public")
        .expect("must have a public note");
    assert_eq!(public.1, "Following up.");
    assert_eq!(
        public.2,
        Some(contact_id),
        "public note must be attributed to the matched sender contact"
    );
}

#[sqlx::test]
async fn every_intake_writes_a_log_row(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let bearer = "phase2-token-log";
    seed_token(&pool, bearer).await;

    sqlx::query(
        r#"INSERT INTO contacts (tenant_id, first_name, last_name, email, company_id)
           VALUES ($1, 'Carol', 'Logger', 'carol@example.com', $2)"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    let app = common::boot(pool.clone()).await;

    let happy: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<phase2-log-happy@example.com>",
            "from_email": "carol@example.com",
            "subject": "Happy",
            "body_text": "ok",
            "raw_headers": {"From": "Carol <carol@example.com>", "X-Test": "yes"},
        }))
        .send()
        .await
        .expect("happy POST")
        .json()
        .await
        .expect("happy body");
    let happy_ticket = happy["ticket_id"].as_str().expect("ticket_id").to_string();

    let stranger = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<phase2-log-stranger@example.com>",
            "from_email": "stranger@example.com",
            "subject": "No",
            "body_text": "nope",
        }))
        .send()
        .await
        .expect("stranger POST");
    assert_eq!(stranger.status().as_u16(), 400);

    let rows: Vec<(Uuid, String, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT id, message_id, ticket_id, error FROM email_intake_log \
         WHERE tenant_id = $1 ORDER BY received_at",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_all(&pool)
    .await
    .expect("log rows");
    assert_eq!(rows.len(), 2, "exactly two log rows for the two POSTs");

    let happy_row = rows
        .iter()
        .find(|(_, m, _, _)| m == "<phase2-log-happy@example.com>")
        .expect("happy log row");
    assert_eq!(
        happy_row.2.map(|t| t.to_string()),
        Some(happy_ticket.clone()),
        "happy log row carries the resulting ticket_id"
    );
    assert!(happy_row.3.is_none(), "happy log row has no error");

    let stranger_row = rows
        .iter()
        .find(|(_, m, _, _)| m == "<phase2-log-stranger@example.com>")
        .expect("stranger log row");
    assert!(
        stranger_row.2.is_none(),
        "stranger log row has no ticket_id"
    );
    assert!(
        stranger_row.3.as_deref().is_some_and(|s| !s.is_empty()),
        "stranger log row carries an error string; got {stranger_row:?}"
    );

    // Admin GET surfaces the row.
    let token = common::login(&app, &email, &password).await;
    let fetched: Value = app
        .client
        .get(app.url(&format!("/api/v1/email-intake-log/{}", stranger_row.0)))
        .bearer_auth(&token)
        .send()
        .await
        .expect("GET intake-log")
        .json()
        .await
        .expect("intake-log body");
    assert_eq!(
        fetched["id"].as_str(),
        Some(stranger_row.0.to_string().as_str())
    );
    assert!(fetched["error"].as_str().is_some());
    assert!(fetched["ticket_id"].is_null());
}
