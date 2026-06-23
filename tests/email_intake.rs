//! PMS-450 phase 1: integration test for email-to-ticket intake.
//!
//! Drives the real HTTP surface with a seeded tenant_intake_token and
//! a seeded contact. Exercises:
//!   - happy path (one POST -> one ticket created, source='email');
//!   - dedup (same Message-Id replayed -> same ticket id, deduplicated=true);
//!   - threading (References pointing at the prior ticket's Message-Id
//!     -> same ticket id, threaded=true);
//!   - reject (unknown From -> 400);
//!   - reject (no/bad bearer -> 401).

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

#[sqlx::test]
async fn email_intake_happy_dedup_thread(pool: PgPool) {
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;

    // Seed a contact in the default tenant the email-intake will
    // match against. The From: address (lowercased) must equal the
    // contact email for the intake to find it.
    let contact_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO contacts (id, tenant_id, first_name, last_name, email, company_id)
           VALUES ($1, $2, 'Alice', 'Sender', 'alice@example.com', $3)"#,
    )
    .bind(contact_id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    // Seed an active intake token. Plaintext "test-intake-token";
    // store the SHA-256 hex.
    let bearer = "test-intake-token-abcdef";
    sqlx::query(
        r#"INSERT INTO tenant_intake_tokens (tenant_id, kind, token_hash, label)
           VALUES ($1, 'email_intake', $2, 'integration test gateway')"#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(sha256_hex(bearer.as_bytes()))
    .execute(&pool)
    .await
    .expect("seed intake token");

    let app = common::boot(pool).await;

    // Happy path: a fresh Message-Id creates a ticket.
    let first_message_id = "<msg-1@example.com>";
    let first: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": first_message_id,
            "from_email": "alice@example.com",
            "from_name": "Alice Sender",
            "subject": "Printer is jammed again",
            "body_text": "Hi team, the third-floor printer is jammed. Can someone help?",
        }))
        .send()
        .await
        .expect("happy POST")
        .json()
        .await
        .expect("happy body");
    assert_eq!(first["created"], true);
    assert_eq!(first["deduplicated"], false);
    assert_eq!(first["threaded"], false);
    let ticket_id = first["ticket_id"].as_str().expect("ticket_id").to_string();
    let ticket_number = first["ticket_number"]
        .as_str()
        .expect("ticket_number")
        .to_string();
    assert!(!ticket_number.is_empty(), "ticket should have a number");

    // Dedup: replaying the same Message-Id returns the SAME ticket
    // with `deduplicated=true`. Idempotent gateway retries land
    // here.
    let replayed: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": first_message_id,
            "from_email": "alice@example.com",
            "subject": "Printer is jammed again",
            "body_text": "Hi team, the third-floor printer is jammed. Can someone help?",
        }))
        .send()
        .await
        .expect("replay POST")
        .json()
        .await
        .expect("replay body");
    assert_eq!(replayed["created"], false);
    assert_eq!(replayed["deduplicated"], true);
    assert_eq!(replayed["ticket_id"].as_str(), Some(ticket_id.as_str()));

    // Threading: a new Message-Id with a References array that
    // includes the first ticket's Message-Id routes the intake onto
    // that ticket (returns its id with threaded=true). Phase 1
    // returns the existing id; Phase 2 will append a comment.
    let threaded: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<msg-2-reply@example.com>",
            "from_email": "alice@example.com",
            "subject": "Re: Printer is jammed again",
            "body_text": "Following up - still jammed.",
            "references": [first_message_id, "<unrelated@example.com>"],
        }))
        .send()
        .await
        .expect("threaded POST")
        .json()
        .await
        .expect("threaded body");
    assert_eq!(threaded["created"], false);
    assert_eq!(threaded["threaded"], true);
    assert_eq!(threaded["ticket_id"].as_str(), Some(ticket_id.as_str()));

    // Unknown From: 400. The sender must be a known tenant contact.
    let rejected = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({
            "message_id": "<msg-3@example.com>",
            "from_email": "stranger@example.com",
            "subject": "Hi",
            "body_text": "I just discovered your helpdesk",
        }))
        .send()
        .await
        .expect("stranger POST");
    assert_eq!(rejected.status().as_u16(), 400);

    // Bad bearer: 401. Authentication failure.
    let bad_bearer = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth("totally-wrong-bearer")
        .json(&serde_json::json!({
            "message_id": "<msg-4@example.com>",
            "from_email": "alice@example.com",
            "subject": "Hi",
            "body_text": "Hello",
        }))
        .send()
        .await
        .expect("bad bearer POST");
    assert_eq!(bad_bearer.status().as_u16(), 401);

    // No bearer at all: 401. (The validate() check on the body runs
    // BEFORE the bearer extraction in the handler ordering, so the
    // body must still be valid here for the test to assert the auth
    // path. With a valid body, missing-bearer falls through to 401.)
    let no_bearer = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .json(&serde_json::json!({
            "message_id": "<msg-5@example.com>",
            "from_email": "alice@example.com",
            "subject": "Hi",
            "body_text": "Hello",
        }))
        .send()
        .await
        .expect("no bearer POST");
    assert_eq!(no_bearer.status().as_u16(), 401);

    // Only one ticket was created across the whole run; dedup +
    // threading must not have multiplied rows.
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM tickets WHERE tenant_id = $1 AND source = 'email'")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(&app.pool)
            .await
            .expect("ticket count");
    assert_eq!(count.0, 1, "exactly one email-source ticket should exist");
}
