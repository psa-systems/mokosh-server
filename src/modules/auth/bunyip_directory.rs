//! PMS-1208: client for Bunyip's user-directory lookup.
//!
//! In the SaaS deployment mokosh-server needs to check whether an
//! email resolves to a Bunyip identity BEFORE it creates a pending
//! grant invitation, so a grant to an unknown-to-Bunyip address is
//! refused at invitation-create time (a clean 422 pointing the
//! owner at "ask them to sign up first") rather than reaching a
//! dead end at accept time.
//!
//! This module is the client half of that: HTTP Basic to
//! `GET {BUNYIP_API_BASE_URL}/v1/users/lookup?email={address}` with
//! the deployment's machine credential, returning `Ok(Some(user_id))`
//! on a match, `Ok(None)` on a 404 (unknown or soft-deleted), or an
//! `AppError` on transport failure.
//!
//! Deployment-mode wiring lives at the constructor. `from_config`
//! returns `Ok(None)` when the three environment values are unset,
//! which is the standalone-mode signal: the handler's caller then
//! skips the lookup and creates the invitation email-only. A
//! deployment mis-configured with a partial set (some values but
//! not all three) is a boot warning, because the operator almost
//! certainly meant to enable the client and forgot one value.
//!
//! Rate-limiting on the Bunyip side is `RateLimitConfig::USER_LOOKUP`
//! (60/min per calling app); on this side the human path is bounded
//! by the invitation-create endpoint's own admin gate. Errors from
//! Bunyip surface unchanged; 5xx from the transport becomes an
//! `AppError::Internal` and refuses the invitation, so a Bunyip
//! outage does NOT silently degrade to "create it anyway."

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Deserialize;
use uuid::Uuid;

use crate::config;
use crate::config::registry::{
    BUNYIP_API_BASE_URL, BUNYIP_DIRECTORY_CLIENT_ID, BUNYIP_DIRECTORY_CLIENT_SECRET,
};
use crate::utils::error::{AppError, AppResult};

/// Wire shape of `GET /v1/users/lookup` from bunyip-api. Only the
/// `user_id` matters here; `email` is kept for observability.
#[derive(Debug, Deserialize)]
struct LookupResponse {
    #[serde(default)]
    data: Option<LookupData>,
}

#[derive(Debug, Deserialize)]
struct LookupData {
    user_id: String,
    #[allow(dead_code)]
    email: String,
}

/// A client that can resolve an email to a Bunyip user id. Cheap to
/// clone (holds a `reqwest::Client`); construct once at boot and
/// share across handlers through `Arc`.
#[derive(Clone)]
pub struct BunyipUserDirectory {
    http: reqwest::Client,
    base_url: String,
    /// Precomputed HTTP Basic header value so every call skips the
    /// base64 encoding step.
    basic_header: String,
}

impl BunyipUserDirectory {
    /// Build a client from configuration. Returns `Ok(None)` when
    /// all three keys are unset (standalone mode, no directory
    /// call to make); `Ok(Some(_))` when all three are set; and
    /// `Err` when the shape is partial - the deployment almost
    /// certainly meant to enable the client and left a value out,
    /// and silently disabling it hides the misconfiguration.
    pub fn from_config() -> AppResult<Option<Self>> {
        let base = config::get(&BUNYIP_API_BASE_URL)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let client_id = config::get(&BUNYIP_DIRECTORY_CLIENT_ID)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let secret = config::get(&BUNYIP_DIRECTORY_CLIENT_SECRET)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        match (base, client_id, secret) {
            (None, None, None) => Ok(None),
            (Some(base), Some(id), Some(secret)) => {
                let http = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|e| {
                        AppError::internal(format!("build bunyip directory client: {e}"))
                    })?;
                let basic = B64.encode(format!("{id}:{secret}"));
                Ok(Some(Self {
                    http,
                    base_url: base.trim_end_matches('/').to_string(),
                    basic_header: format!("Basic {basic}"),
                }))
            }
            _ => Err(AppError::internal(
                "BUNYIP_API_BASE_URL / BUNYIP_DIRECTORY_CLIENT_ID / \
                 BUNYIP_DIRECTORY_CLIENT_SECRET must be set together or all left unset.",
            )),
        }
    }

    /// Look one email up. Returns:
    /// - `Ok(Some(user_id))` on a Bunyip match.
    /// - `Ok(None)` on 404 (unknown to Bunyip or soft-deleted).
    /// - `Err(AppError::Internal)` on transport failure or a non-2xx
    ///   non-404 response, so a Bunyip outage refuses the caller's
    ///   invitation rather than silently degrading to "create it
    ///   anyway."
    #[tracing::instrument(skip(self), fields(email = %redact(email)))]
    pub async fn lookup(&self, email: &str) -> AppResult<Option<Uuid>> {
        let url = format!("{}/v1/users/lookup", self.base_url);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", &self.basic_header)
            .query(&[("email", email)])
            .send()
            .await
            .map_err(|e| AppError::internal(format!("bunyip directory transport: {e}")))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                status = %status,
                body = %body.chars().take(200).collect::<String>(),
                "bunyip directory lookup returned a non-2xx"
            );
            return Err(AppError::internal(format!(
                "bunyip directory lookup returned status {status}"
            )));
        }

        let body: LookupResponse = resp.json().await.map_err(|e| {
            AppError::internal(format!("bunyip directory response was not JSON: {e}"))
        })?;
        let data = body.data.ok_or_else(|| {
            AppError::internal("bunyip directory 2xx response had no `data` field")
        })?;
        Uuid::parse_str(&data.user_id).map(Some).map_err(|_| {
            AppError::internal(format!(
                "bunyip directory returned a non-UUID user_id: {}",
                data.user_id
            ))
        })
    }
}

/// Log-friendly redaction of an email address for observability.
/// `alice@example.com` becomes `a****@example.com` so the domain
/// stays visible for debugging while the local part is not.
fn redact(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().unwrap_or('?');
            format!("{first}****@{domain}")
        }
        None => "<invalid>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_the_local_part_but_keeps_the_domain() {
        assert_eq!(redact("alice@example.com"), "a****@example.com");
        assert_eq!(redact("a@b"), "a****@b");
        assert_eq!(redact("bogus"), "<invalid>");
    }
}
