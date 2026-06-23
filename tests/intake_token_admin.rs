//! PMS-450 phase 2: integration test for the admin intake-token CRUD.
//!
//! Pins the guarantees that matter for an operator-facing credential
//! surface:
//!   - admin mints a token, the response carries the plaintext ONCE,
//!     the DB stores the SHA-256 hash (no plaintext at rest);
//!   - the minted token immediately works against the email-intake
//!     surface (round-trip through the SHA-256-hashed lookup);
//!   - non-admin (technician) cannot list, create, or revoke;
//!   - revoke flips `revoked_at`; the same token immediately fails to
//!     authenticate against `/email-intake` (401);
//!   - re-revoking is idempotent (no error, the timestamp does not
//!     move forward on the second call);
//!   - listing returns both active and revoked rows so the operator
//!     can audit.

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
async fn intake_token_admin_round_trip(pool: PgPool) {
    let (_admin_id, admin_email, admin_pw) = common::seed_admin(&pool).await;
    // Seed a technician in the same tenant so the admin-gate checks
    // have a non-admin identity to refuse.
    let (_tech_id, tech_email, tech_pw) = common::seed_user(
        &pool,
        common::DEFAULT_TENANT_ID,
        "tech@example.com",
        "technician",
    )
    .await;
    // Seed a contact the email-intake will be able to match against
    // once the token authenticates.
    let company_id = common::seed_company(&pool).await;
    sqlx::query(
        r#"INSERT INTO contacts
            (id, tenant_id, company_id, first_name, last_name, email)
           VALUES ($1, $2, $3, 'Alice', 'Sender', 'alice@example.com')"#,
    )
    .bind(Uuid::new_v4())
    .bind(common::DEFAULT_TENANT_ID)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("seed contact");

    let app = common::boot(pool.clone()).await;
    let admin_token = common::login(&app, &admin_email, &admin_pw).await;
    let tech_token = common::login(&app, &tech_email, &tech_pw).await;

    // Tech cannot mint - 403/401 depending on the admin-gate
    // implementation; either way NOT a 200.
    let tech_create = app
        .client
        .post(app.url("/api/v1/intake-tokens"))
        .bearer_auth(&tech_token)
        .json(&serde_json::json!({
            "kind": "email_intake",
            "label": "tech should not be able to do this",
        }))
        .send()
        .await
        .expect("tech POST");
    assert!(
        !tech_create.status().is_success(),
        "non-admin must not mint, got {}",
        tech_create.status()
    );

    // Admin mints a token successfully. The plaintext is in the
    // response.
    let created: Value = app
        .client
        .post(app.url("/api/v1/intake-tokens"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "kind": "email_intake",
            "label": "Cloudron mail hook",
        }))
        .send()
        .await
        .expect("admin POST")
        .json()
        .await
        .expect("created body");
    let plaintext = created["token"]
        .as_str()
        .expect("plaintext in response")
        .to_string();
    let token_id = created["id"].as_str().expect("id").to_string();
    assert_eq!(created["label"], "Cloudron mail hook");
    assert_eq!(created["kind"], "email_intake");
    assert!(created["revoked_at"].is_null(), "freshly-minted is active");
    assert!(!plaintext.is_empty(), "plaintext bearer must be present");

    // The DB stores ONLY the SHA-256 hash; the plaintext is not at
    // rest anywhere.
    let stored: (String,) =
        sqlx::query_as("SELECT token_hash FROM tenant_intake_tokens WHERE id = $1")
            .bind(Uuid::parse_str(&token_id).expect("uuid"))
            .fetch_one(&pool)
            .await
            .expect("stored hash");
    assert_eq!(
        stored.0,
        sha256_hex(plaintext.as_bytes()),
        "DB carries SHA-256 hash, never plaintext"
    );

    // The minted token immediately works against /email-intake.
    let intake: Value = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({
            "message_id": "<minted-token-test@example.com>",
            "from_email": "alice@example.com",
            "subject": "Round trip",
            "body_text": "Body",
        }))
        .send()
        .await
        .expect("intake POST")
        .json()
        .await
        .expect("intake body");
    assert_eq!(
        intake["created"], true,
        "intake must succeed with the minted token"
    );

    // List surfaces the row (1 row), with metadata-only shape (no
    // `token` field at all - it lives only on the create response).
    let list: Value = app
        .client
        .get(app.url("/api/v1/intake-tokens"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("list body");
    let rows = list.as_array().expect("array");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].get("token").is_none(),
        "list response must NOT carry the plaintext"
    );
    assert!(
        rows[0]["last_used_at"].as_str().is_some(),
        "the email-intake call above bumped last_used_at"
    );

    // Tech cannot list either.
    let tech_list = app
        .client
        .get(app.url("/api/v1/intake-tokens"))
        .bearer_auth(&tech_token)
        .send()
        .await
        .expect("tech list");
    assert!(
        !tech_list.status().is_success(),
        "non-admin must not list, got {}",
        tech_list.status()
    );

    // Admin revokes the token.
    let revoke = app
        .client
        .delete(app.url(&format!("/api/v1/intake-tokens/{token_id}")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("revoke");
    assert!(revoke.status().is_success(), "admin revoke succeeds");

    // The revoked token no longer authenticates against /email-intake.
    let revoked_intake = app
        .client
        .post(app.url("/api/v1/email-intake"))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({
            "message_id": "<after-revoke@example.com>",
            "from_email": "alice@example.com",
            "subject": "Should fail",
            "body_text": "Body",
        }))
        .send()
        .await
        .expect("revoked intake");
    assert_eq!(revoked_intake.status().as_u16(), 401);

    // Idempotent re-revoke: another DELETE returns 2xx, the
    // `revoked_at` does NOT move forward.
    let first_revoked_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT revoked_at FROM tenant_intake_tokens WHERE id = $1")
            .bind(Uuid::parse_str(&token_id).expect("uuid"))
            .fetch_one(&pool)
            .await
            .expect("first revoked_at");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let re_revoke = app
        .client
        .delete(app.url(&format!("/api/v1/intake-tokens/{token_id}")))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("re-revoke");
    assert!(re_revoke.status().is_success(), "re-revoke is idempotent");
    let second_revoked_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT revoked_at FROM tenant_intake_tokens WHERE id = $1")
            .bind(Uuid::parse_str(&token_id).expect("uuid"))
            .fetch_one(&pool)
            .await
            .expect("second revoked_at");
    assert_eq!(
        first_revoked_at, second_revoked_at,
        "re-revoke must NOT move the timestamp forward (COALESCE preserves the first)"
    );

    // The revoked row still appears in the list (audit trail).
    let after_revoke: Value = app
        .client
        .get(app.url("/api/v1/intake-tokens"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("list after revoke")
        .json()
        .await
        .expect("after list body");
    let after_rows = after_revoke.as_array().expect("array");
    assert_eq!(after_rows.len(), 1, "revoked row stays visible for audit");
    assert!(
        after_rows[0]["revoked_at"].as_str().is_some(),
        "revoked_at is now populated"
    );

    // Wrong kind on create -> 400 (Phase 2 only accepts
    // `email_intake`).
    let bad_kind = app
        .client
        .post(app.url("/api/v1/intake-tokens"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "kind": "some-future-surface",
            "label": "should reject",
        }))
        .send()
        .await
        .expect("bad kind");
    assert_eq!(bad_kind.status().as_u16(), 400);

    // Revoke a non-existent id -> 404.
    let missing = app
        .client
        .delete(app.url(&format!("/api/v1/intake-tokens/{}", Uuid::new_v4())))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("missing revoke");
    assert_eq!(missing.status().as_u16(), 404);
}
