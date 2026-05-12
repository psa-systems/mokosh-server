//! `/v1/auth/mfa/*` - TOTP enrollment + verify.
//!
//! `setup` and `confirm` are admin-of-self: they live behind the
//! `BearerUser` extractor, take the calling user as the subject, and
//! never accept an explicit user_id. The verify endpoint that completes
//! a two-step login lives in `auth.rs` because it sits in the login
//! response flow.
//!
//! See docs/mokosh-mfa/02-enrollment-endpoints.md.
//!
//! For the in-progress / rolled-back enrollment cases we follow the
//! same pattern as password-reset: idempotent under repeated POSTs; a
//! refresh of the setup page yields a fresh secret + fresh codes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use mokosh_auth_core::{AuditEvent, AuthError};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

#[derive(Debug, Serialize)]
pub struct SetupResponse {
    pub secret: String,
    pub provisioning_uri: String,
    pub qr_svg: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmBody {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct ConfirmResponse {
    pub mfa_enrolled: bool,
}

/// `POST /v1/auth/mfa/setup`
///
/// Issues a fresh secret (rotates any unconfirmed prior secret) and a
/// fresh set of recovery codes. Caller must complete `/confirm` with a
/// code from their authenticator before `mfa_enrolled` flips.
pub async fn setup(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
) -> Result<Response, HttpError> {
    if let Err(rl) = st.rate_limiter.check_mfa_setup(user.id) {
        return Ok(rl.into_response());
    }

    // 1. Encrypt a fresh secret under the active DEK version. The
    //    storage repo is responsible for the row's idempotency; the
    //    handler just hands it the bytes.
    let raw_secret = mokosh_auth_crypto::totp::generate_secret();
    let blob = st
        .dek
        .encrypt(&raw_secret)
        .map_err(|e| HttpError(AuthError::Crypto(format!("dek encrypt: {e}"))))?;
    let blob_json = serde_json::to_value(&blob)
        .map_err(|e| HttpError(AuthError::Internal(format!("dek serialize: {e}"))))?;

    let enrollment = st
        .totp
        .start_enrollment(user.id, user.tenant_id, blob_json, st.dek_version)
        .await?;

    // 2. The storage layer might have returned an existing unconfirmed
    //    row (whose secret was rotated to the one we just produced) or
    //    a fresh insert. Either way the secret we sent down is the one
    //    that is going back to the user. Decrypt it again so we can
    //    show it (no-op for new rows; load-bearing for the rotate path
    //    where we want the freshly-stored value, not the bytes
    //    `start_enrollment` overwrote in place).
    let stored_blob: mokosh_auth_crypto::EncryptedBlob =
        serde_json::from_value(enrollment.secret_encrypted.clone())
            .map_err(|e| HttpError(AuthError::Storage(format!("blob deserialize: {e}"))))?;
    let secret_bytes = st
        .dek
        .decrypt(&stored_blob)
        .map_err(|e| HttpError(AuthError::Crypto(format!("dek decrypt: {e}"))))?;
    let secret_b32 = mokosh_auth_crypto::totp::base32_encode(&secret_bytes);

    // 3. Build the provisioning URI + QR SVG.
    let label = format!("{}:{}", st.mfa_issuer, user.email);
    let provisioning_uri =
        mokosh_auth_crypto::totp::provisioning_uri(&secret_b32, &label, &st.mfa_issuer);
    let qr_svg = render_qr_svg(&provisioning_uri)
        .map_err(|e| HttpError(AuthError::Internal(format!("qr render: {e}"))))?;

    // 4. Generate + persist a fresh set of recovery codes. We do this
    //    here (not in `confirm`) so the user sees them at the same
    //    time they see the QR; the SPA is responsible for warning the
    //    user that re-loading the page invalidates the previous set.
    let recovery_codes = mokosh_auth_crypto::recovery::generate_set();
    let hashes: Vec<[u8; 32]> = recovery_codes
        .iter()
        .map(|c| mokosh_auth_crypto::recovery::hash_code(c))
        .collect();
    st.recovery_codes
        .replace_all(user.id, user.tenant_id, enrollment.id, &hashes)
        .await?;

    let _ = st
        .provider
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            None,
            AuditEvent::TotpEnrollmentStarted { user_id: user.id },
        )
        .await;
    let _ = st
        .provider
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            None,
            AuditEvent::RecoveryCodesIssued {
                user_id: user.id,
                count: recovery_codes.len(),
            },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(SetupResponse {
            secret: secret_b32,
            provisioning_uri,
            qr_svg,
            recovery_codes,
        }),
    )
        .into_response())
}

/// `POST /v1/auth/mfa/confirm`
///
/// Validates that the user can compute a TOTP code against the secret
/// `setup` issued and flips `mfa_enrolled = TRUE`. Idempotent failure
/// modes: missing enrollment row -> 404; already confirmed -> 409.
pub async fn confirm(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
    Json(body): Json<ConfirmBody>,
) -> Result<Response, HttpError> {
    if let Err(rl) = st.rate_limiter.check_mfa_confirm(user.id) {
        return Ok(rl.into_response());
    }

    let enrollment = match st.totp.find_for_user(user.id).await? {
        Some(e) if !e.is_confirmed() => e,
        Some(_) => {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({"error": "already_enrolled"})),
            )
                .into_response());
        }
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({"error": "not_setup"})),
            )
                .into_response());
        }
    };

    let stored_blob: mokosh_auth_crypto::EncryptedBlob =
        serde_json::from_value(enrollment.secret_encrypted.clone())
            .map_err(|e| HttpError(AuthError::Storage(format!("blob deserialize: {e}"))))?;
    let secret_bytes = st
        .dek
        .decrypt(&stored_blob)
        .map_err(|e| HttpError(AuthError::Crypto(format!("dek decrypt: {e}"))))?;

    let step = match mokosh_auth_crypto::totp::verify(&secret_bytes, &body.code, Utc::now(), 1) {
        Some(s) => s,
        None => {
            let _ = st
                .provider
                .audit
                .record(
                    Some(user.tenant_id),
                    Some(user.id),
                    None,
                    AuditEvent::MfaVerifyFailed {
                        user_id: Some(user.id),
                        reason: "wrong_totp".into(),
                        ip: None,
                    },
                )
                .await;
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_code", "reason": "wrong_code"})),
            )
                .into_response());
        }
    };

    // Consume the step BEFORE we flip mfa_enrolled, so a parallel
    // confirm with the same code (e.g. two browser tabs) does not get
    // through. `consume_step` is an UPDATE with a strict-greater-than
    // race guard; the loser sees `replayed_step`.
    if let Err(AuthError::InvalidGrant(_)) = st.totp.consume_step(user.id, step).await {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_code", "reason": "code_replayed"})),
        )
            .into_response());
    }

    // The recovery codes are already in the DB from /mfa/setup; confirm
    // is just the flag flip + the confirmed_at write under SERIALIZABLE.
    st.totp.confirm(user.id).await?;

    let _ = st
        .provider
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            None,
            AuditEvent::TotpEnrolled { user_id: user.id },
        )
        .await;

    Ok((
        StatusCode::OK,
        Json(ConfirmResponse { mfa_enrolled: true }),
    )
        .into_response())
}

/// Render a black-on-white SVG QR encoding `data`. The SPA inlines this
/// directly so there is no QR-encoder JS bundle and no first-render
/// flash.
fn render_qr_svg(data: &str) -> Result<String, String> {
    use qrcode::render::svg;
    use qrcode::QrCode;
    let qr = QrCode::new(data.as_bytes()).map_err(|e| e.to_string())?;
    Ok(qr
        .render::<svg::Color>()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}
