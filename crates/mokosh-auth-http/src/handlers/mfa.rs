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

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use chrono::Utc;
use mokosh_auth_core::{AuditEvent, AuthError, MfaChallengePurpose, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cookies::set_op_session_cookie;
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

#[derive(Debug, Deserialize)]
pub struct VerifyBody {
    pub challenge: String,
    pub code: String,
}

/// `POST /v1/auth/mfa/verify`
///
/// Consumes the login challenge issued by `/v1/auth/login`, validates a
/// TOTP code or a recovery code, creates the op_session (with the
/// stronger `acr = urn:mokosh:loa:mfa`), and returns the same shape the
/// regular login response uses for a non-MFA account.
pub async fn verify(
    State(st): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Json(body): Json<VerifyBody>,
) -> Result<Response, HttpError> {
    if let Err(rl) = st.rate_limiter.check_mfa_verify(addr.ip()) {
        return Ok(rl.into_response());
    }
    let ip = Some(addr.ip());
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());

    let token_hash = mokosh_auth_crypto::hash_opaque_token(&body.challenge);
    // Validate purpose + freshness + consumed under the SERIALIZABLE
    // tx; the repo also marks the row consumed in the same tx.
    let challenge = match st
        .mfa_challenges
        .consume(token_hash, MfaChallengePurpose::Login)
        .await
    {
        Ok(c) => c,
        Err(AuthError::NotFound) => {
            let _ = st
                .provider
                .audit
                .record(
                    None,
                    None,
                    ip,
                    AuditEvent::MfaVerifyFailed {
                        user_id: None,
                        reason: "unknown_or_used_or_expired".into(),
                        ip: ip.map(|i| i.to_string()),
                    },
                )
                .await;
            return Ok(challenge_not_found());
        }
        Err(e) => return Err(HttpError(e)),
    };

    let user = st
        .provider
        .users
        .find_by_id(challenge.user_id)
        .await?
        .ok_or(AuthError::AccessDenied("user not found".into()))?;

    // Verify the supplied code. Pick TOTP vs recovery by the input shape:
    // a 6-digit all-numeric string is TOTP; anything else is treated as
    // a recovery code.
    let code = body.code.trim();
    let is_totp = code.len() == 6 && code.chars().all(|c| c.is_ascii_digit());
    let amr_method: &'static str;
    if is_totp {
        let enrollment = st
            .totp
            .find_for_user(user.id)
            .await?
            .ok_or(AuthError::AccessDenied("user not enrolled".into()))?;
        let blob: mokosh_auth_crypto::EncryptedBlob =
            serde_json::from_value(enrollment.secret_encrypted.clone())
                .map_err(|e| HttpError(AuthError::Storage(format!("blob deserialize: {e}"))))?;
        let secret = st
            .dek
            .decrypt(&blob)
            .map_err(|e| HttpError(AuthError::Crypto(format!("dek decrypt: {e}"))))?;
        let step = match mokosh_auth_crypto::totp::verify(&secret, code, Utc::now(), 1) {
            Some(s) => s,
            None => {
                let _ = st
                    .provider
                    .audit
                    .record(
                        Some(user.tenant_id),
                        Some(user.id),
                        ip,
                        AuditEvent::MfaVerifyFailed {
                            user_id: Some(user.id),
                            reason: "wrong_totp".into(),
                            ip: ip.map(|i| i.to_string()),
                        },
                    )
                    .await;
                return Ok(invalid_code(user.id));
            }
        };
        if let Err(AuthError::InvalidGrant(_)) = st.totp.consume_step(user.id, step).await {
            let _ = st
                .provider
                .audit
                .record(
                    Some(user.tenant_id),
                    Some(user.id),
                    ip,
                    AuditEvent::MfaVerifyFailed {
                        user_id: Some(user.id),
                        reason: "code_replayed".into(),
                        ip: ip.map(|i| i.to_string()),
                    },
                )
                .await;
            return Ok(invalid_code(user.id));
        }
        amr_method = "totp";
    } else {
        let hash = mokosh_auth_crypto::recovery::hash_code(code);
        match st.recovery_codes.consume_unused(user.id, hash).await {
            Ok(()) => {
                let _ = st
                    .provider
                    .audit
                    .record(
                        Some(user.tenant_id),
                        Some(user.id),
                        ip,
                        AuditEvent::RecoveryCodeUsed {
                            user_id: user.id,
                            ip: ip.map(|i| i.to_string()),
                        },
                    )
                    .await;
                amr_method = "recovery";
            }
            Err(AuthError::NotFound) => {
                let _ = st
                    .provider
                    .audit
                    .record(
                        Some(user.tenant_id),
                        Some(user.id),
                        ip,
                        AuditEvent::MfaVerifyFailed {
                            user_id: Some(user.id),
                            reason: "wrong_recovery".into(),
                            ip: ip.map(|i| i.to_string()),
                        },
                    )
                    .await;
                return Ok(invalid_code(user.id));
            }
            Err(e) => return Err(HttpError(e)),
        }
    }

    let amr = vec!["pwd".to_string(), amr_method.to_string()];
    let session = st
        .local_auth
        .create_session(&user, ip, ua, "urn:mokosh:loa:mfa", &amr)
        .await?;
    let _ = st
        .provider
        .audit
        .record(
            Some(user.tenant_id),
            Some(user.id),
            ip,
            AuditEvent::MfaChallengeConsumed {
                user_id: user.id,
                method: amr_method.to_string(),
            },
        )
        .await;

    // Mint OIDC tokens if the original login carried a client_id.
    let tokens = if let Some(client_id) = challenge.client_id {
        Some(
            crate::handlers::auth::mint_first_party_tokens_for(
                &st,
                &user,
                &session,
                client_id.0,
                &challenge.scope,
                challenge.active_tenant_id,
            )
            .await?,
        )
    } else {
        None
    };

    let cookie = set_op_session_cookie(&st.cookie_cfg, session.sid.clone(), st.provider.cfg.op_session_ttl);
    let body = json!({
        "user_id":          user.id.0.to_string(),
        "tenant_id":        user.tenant_id.0.to_string(),
        "active_tenant_id": challenge.active_tenant_id.0.to_string(),
        "tokens":           tokens,
    });
    Ok((jar.add(cookie), Json(body)).into_response())
}

fn challenge_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "challenge_not_found"})),
    )
        .into_response()
}

fn invalid_code(_user_id: UserId) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "invalid_code"})),
    )
        .into_response()
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
