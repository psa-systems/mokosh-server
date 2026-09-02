//! PMS-591: receiver for Bunyip's `account_deleted` webhook.
//!
//! Bunyip's BUNYIP-211 webhook dispatcher fires
//! `POST {app.webhook_url}` with body
//! `{"event":"account_deleted","user_id":"<uuid>","timestamp":"<rfc3339>"}`
//! and header `X-Webhook-Signature: <hex hmac_sha256(body, shared_secret)>`
//! whenever a Bunyip account is deleted. Mokosh's mirrored user row is keyed
//! by `users.id = <bunyip sub>` per the PMS-295 cutover, so the same UUID
//! that bunyip sends in `user_id` addresses the mokosh row directly - no
//! `bunyip_sub` column needed.
//!
//! Tombstone posture (soft delete):
//! - `users.deleted_at = NOW()` (from migration 087)
//! - `users.email = deleted-<uuid>@deleted.local` so the `UNIQUE(tenant_id,
//!   email)` constraint does not block a future signup with the same address
//! - `DELETE FROM user_sessions WHERE user_id = ...` (revokes legacy HS256)
//! - `DELETE FROM api_keys WHERE user_id = ...` (revokes issued API keys)
//! - `DELETE FROM password_reset_tokens WHERE user_id = ...` (defence-in-depth)
//! - `INSERT INTO audit_log` with `action='delete'`, `entity_type='users'`
//!
//! Cross-tenant history stays: `time_entries`, `contracts`, `audit_log` rows
//! that reference the tombstoned user by id are untouched. The mokosh-side
//! auth lookups (`get_user_by_id`, `find_user_placement`) filter
//! `deleted_at IS NULL` so a stale bunyip JWT arriving after tombstone
//! resolves to `NotFound` and returns 401.
//!
//! Idempotent: a replay of the same payload no-ops (already-tombstoned user
//! returns 200 without re-executing the tx). BUNYIP-211's 3-attempt retry
//! budget can therefore hammer the endpoint safely.
//!
//! Route: `POST /api/v1/bunyip/webhooks/account-deleted`. Wired outside the
//! JWT auth middleware (this endpoint authenticates itself via HMAC, not via
//! `AuthState`).

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::utils::error::{AppError, AppResult};

/// Shared HMAC secret + database pool the receiver needs. Threaded via
/// `Arc<BunyipWebhookState>` at router-build time; not part of `AuthMiddleware`
/// because the webhook lives outside the auth chain.
#[derive(Clone)]
pub struct BunyipWebhookState {
    pub pool: PgPool,
    pub webhook_secret: Vec<u8>,
}

/// BUNYIP-211's payload shape. Only `event` + `user_id` are load-bearing;
/// `timestamp` is captured but not authenticated beyond the HMAC over the
/// wire bytes.
#[derive(Debug, Deserialize)]
struct AccountDeletedPayload {
    event: String,
    user_id: Uuid,
    #[serde(default)]
    #[allow(dead_code)]
    timestamp: Option<String>,
}

const EVENT_ACCOUNT_DELETED: &str = "account_deleted";
const SIGNATURE_HEADER: &str = "X-Webhook-Signature";
const TOMBSTONE_EMAIL_DOMAIN: &str = "@deleted.local";

/// Handler for `POST /api/v1/bunyip/webhooks/account-deleted`.
pub async fn account_deleted(
    State(state): State<Arc<BunyipWebhookState>>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    // 1. Extract the signature header (missing / non-ASCII = 401).
    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    // 2. Verify HMAC over the RAW wire bytes. Re-serialising the parsed JSON
    //    reorders fields / normalises whitespace and would invalidate a
    //    legitimate signature.
    verify_signature(&state.webhook_secret, &body, signature)?;

    // 3. Only then parse the body. Order matters: an unauthenticated body must
    //    not reach the JSON parser at all.
    let payload: AccountDeletedPayload = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("Malformed webhook body".to_string()))?;

    if payload.event != EVENT_ACCOUNT_DELETED {
        return Err(AppError::BadRequest(format!(
            "Unsupported event {:?}",
            payload.event
        )));
    }

    // 4. Idempotent tombstone. A missing user is 200 (Bunyip may have deleted
    //    a user that never signed into mokosh); an already-tombstoned user is
    //    200 (BUNYIP-211's retry budget can replay). Only a genuinely-live user
    //    triggers the tx.
    soft_delete(&state.pool, payload.user_id).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "user_id": payload.user_id})),
    ))
}

/// Verify `expected_hex == hex(hmac_sha256(body, secret))` in constant time.
/// Returns `Unauthorized` on any mismatch or malformed input.
fn verify_signature(secret: &[u8], body: &[u8], expected_hex: &str) -> AppResult<()> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).map_err(|_| AppError::Unauthorized)?;
    mac.update(body);
    let computed = mac.finalize().into_bytes();
    let computed_hex = hex_encode(&computed);
    if constant_time_eq::constant_time_eq(computed_hex.as_bytes(), expected_hex.as_bytes()) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Lowercase hex encoding. Zero-dep hand-roll so the module does not pull in
/// the `hex` crate for four lines of encoding.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Soft-delete a user by id. No-op if the row is missing or already tombstoned.
///
/// Runs on the migrator pool (BYPASSRLS) because the webhook has no tenant
/// context - the tenant_id is discovered from the target row, not asserted by
/// the caller. Everything the webhook writes is keyed by user_id, so RLS on
/// the user's own tenant does not offer meaningful additional isolation here.
async fn soft_delete(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    // Resolve the tenant_id + live-ness in one query so we can decide
    // idempotently without a second round-trip.
    let existing: Option<(Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as("SELECT tenant_id, deleted_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let Some((tenant_id, deleted_at)) = existing else {
        // User row was never mirrored into mokosh (they signed up on Bunyip
        // but never authenticated to mokosh). Nothing to tombstone; report
        // success so BUNYIP-211 does not retry into an audit-log row.
        return Ok(());
    };

    if deleted_at.is_some() {
        // Already tombstoned by a prior delivery. No-op.
        return Ok(());
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Tombstone: mark deleted, rewrite email so a future signup can reuse
    // the address without hitting UNIQUE(tenant_id, email).
    let tombstone_email = format!("deleted-{user_id}{TOMBSTONE_EMAIL_DOMAIN}");
    sqlx::query(
        "UPDATE users SET deleted_at = NOW(), email = $2 WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(user_id)
    .bind(&tombstone_email)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Revoke every live artefact that could re-authenticate this user.
    for stmt in [
        "DELETE FROM user_sessions WHERE user_id = $1",
        "DELETE FROM api_keys WHERE user_id = $1",
        "DELETE FROM password_reset_tokens WHERE user_id = $1",
    ] {
        sqlx::query(stmt)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }

    // Audit row. `user_id` (actor) is NULL because the trigger is Bunyip's
    // dispatcher, not a mokosh identity. entity_id points at the tombstoned
    // user so a future admin query can find the deletion event by user id.
    sqlx::query(
        r#"
        INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, new_values)
        VALUES ($1, NULL, 'delete', 'users', $2, $3)
        "#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(serde_json::json!({
        "source": "bunyip_account_deleted_webhook",
        "reason": "user deleted their Bunyip account",
    }))
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(secret: &[u8], body: &[u8]) -> String {
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret).unwrap();
        mac.update(body);
        hex_encode(&mac.finalize().into_bytes())
    }

    #[test]
    fn verify_signature_accepts_matching_hex_hmac() {
        let secret = b"test-secret-abc";
        let body =
            br#"{"event":"account_deleted","user_id":"00000000-0000-0000-0000-000000000001"}"#;
        let sig = signed(secret, body);
        assert!(verify_signature(secret, body, &sig).is_ok());
    }

    #[test]
    fn verify_signature_rejects_wrong_secret() {
        let secret = b"correct-secret";
        let body = br#"{"x":1}"#;
        let sig = signed(b"wrong-secret", body);
        assert!(matches!(
            verify_signature(secret, body, &sig),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn verify_signature_rejects_tampered_body() {
        let secret = b"s";
        let body = br#"{"user_id":"a"}"#;
        let sig = signed(secret, body);
        // Byte-flip the body after signing.
        let tampered = br#"{"user_id":"b"}"#;
        assert!(matches!(
            verify_signature(secret, tampered, &sig),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn verify_signature_rejects_empty_signature() {
        let secret = b"s";
        assert!(matches!(
            verify_signature(secret, b"{}", ""),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn hex_encode_is_lowercase_zero_padded() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff, 0x10]), "000fff10");
    }

    #[test]
    fn payload_deserializes_bunyip_wire_shape() {
        let body =
            br#"{"event":"account_deleted","user_id":"11111111-1111-1111-1111-111111111111","timestamp":"2026-07-02T00:00:00Z"}"#;
        let p: AccountDeletedPayload = serde_json::from_slice(body).unwrap();
        assert_eq!(p.event, "account_deleted");
        assert_eq!(
            p.user_id,
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
        );
    }
}
