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
    /// PMS-1208 finding 7: whether the bunyip identity has verified
    /// its email address. Absent on a bunyip that predates the field;
    /// `#[serde(default)]` reads that as `false` so the mokosh side
    /// refuses the invitation instead of quietly assuming yes and
    /// letting the accept dead-end at placement.
    #[serde(default)]
    email_verified: bool,
}

/// PMS-1208 finding 7: what `lookup` returns to its caller. The
/// existing `bunyip_directory` callers want two properties (does the
/// identity exist? if so, is it verified?), and the mokosh
/// invitation gate turns each into a distinct 422: unregistered is
/// "ask them to sign up first", registered-but-unverified is "ask
/// them to verify their email first". A bare `Uuid` return would
/// hide the second half at the seam.
#[derive(Debug, Clone, Copy)]
pub struct DirectoryHit {
    pub user_id: Uuid,
    pub email_verified: bool,
}

/// MAPPS-875: one active grant returned by `list_owner_grants`. Same
/// field set bunyip's `GET /v1/mokosh-grants` sends, so mokosh does
/// not carry a per-side view struct.
///
/// v2 adds `grantee_email` and `grantee_name`. Both are optional
/// because bunyip's response omits them when the grantee's `users`
/// row has been soft-deleted (the grant stays visible so the owner
/// can revoke it, but there is no identity to render). `#[serde(default)]`
/// keeps the wire compatible with a bunyip build that predates v2.
#[derive(Debug, Clone, Deserialize)]
pub struct OwnerGrantView {
    pub grant_id: Uuid,
    pub grantee_bunyip_user_id: Uuid,
    pub mokosh_account_id: String,
    pub role: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub grantee_email: Option<String>,
    #[serde(default)]
    pub grantee_name: Option<String>,
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
    /// MAPPS-875: test-only constructor for integration tests that
    /// point the client at a mock bunyip HTTP server (`tests/owner_grant_saas.rs`).
    /// Never called in production - `from_config` is the one path
    /// that mints a production instance - but the constructor cannot
    /// be `#[cfg(test)]` because integration tests link this crate
    /// as an external dependency. `#[doc(hidden)]` keeps it out of
    /// the rustdoc public surface.
    #[doc(hidden)]
    pub fn for_tests(base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build test bunyip directory client");
        let basic = B64.encode("test-client-id:test-client-secret");
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            basic_header: format!("Basic {basic}"),
        }
    }

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

    /// PMS-1208 finding 5: register a grant on Bunyip so its
    /// `mokosh_account_grants` table has a row the SPA's later
    /// `POST /v1/grants/{id}/access-token` mint call can find. Called
    /// from `GrantInvitationsService::accept` after the local mirror
    /// upsert lands; the caller passes the mirror's own `grant_id` so
    /// mokosh's `mokosh_bunyip_grants.bunyip_grant_id` and bunyip's
    /// `mokosh_account_grants.id` share the SAME uuid by construction
    /// and no id translation is needed later.
    ///
    /// Behaviour on failure. Standalone mode (`BunyipUserDirectory::from_config`
    /// returned `None`) never calls this at all; the caller is on the
    /// SaaS branch. A transport or non-2xx response returns
    /// `AppError::Internal`, which the accept path surfaces as 500 so
    /// the grantee sees the registration failed rather than a mirror
    /// they cannot switch into. Idempotent by design on bunyip's side
    /// (`ON CONFLICT (id) DO UPDATE`), so a retried accept is safe.
    #[tracing::instrument(skip(self), fields(grant_id = %grant_id))]
    pub async fn register_grant(
        &self,
        grant_id: Uuid,
        owner_bunyip_user_id: Uuid,
        grantee_bunyip_user_id: Uuid,
        mokosh_account_id: &str,
        role: &str,
    ) -> AppResult<()> {
        let url = format!("{}/v1/mokosh-grants", self.base_url);
        let body = serde_json::json!({
            "grant_id": grant_id,
            "owner_bunyip_user_id": owner_bunyip_user_id,
            "grantee_bunyip_user_id": grantee_bunyip_user_id,
            "mokosh_account_id": mokosh_account_id,
            "role": role,
        });
        let resp = self
            .http
            .post(&url)
            .header("Authorization", &self.basic_header)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                AppError::internal(format!("bunyip mokosh-grant register transport: {e}"))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                status = %status,
                body = %body.chars().take(200).collect::<String>(),
                "bunyip mokosh-grant register returned a non-2xx"
            );
            return Err(AppError::internal(format!(
                "bunyip mokosh-grant register returned status {status}"
            )));
        }
        Ok(())
    }

    /// MAPPS-875: list an owner's active outgoing grants on bunyip.
    /// Returns the same shape bunyip's user-authed `list_active_by_owner`
    /// returns, minus revoked rows. Used by mokosh-server's
    /// owner-outbox endpoint to fetch the SaaS-mode authoritative view;
    /// standalone mode reads the local mirror directly and never calls
    /// this method.
    ///
    /// Behaviour on failure. A transport failure or a non-2xx response
    /// returns `AppError::Internal`, so the caller can distinguish an
    /// empty outbox (`Ok(vec![])`) from a bunyip outage. The mokosh
    /// route surfaces the internal error as 500 rather than pretending
    /// the owner has no grants: a false empty on this page would let
    /// them believe access they revoked seconds ago is gone when it is
    /// still active.
    #[tracing::instrument(skip(self), fields(owner = %owner_bunyip_user_id))]
    pub async fn list_owner_grants(
        &self,
        owner_bunyip_user_id: Uuid,
    ) -> AppResult<Vec<OwnerGrantView>> {
        let url = format!("{}/v1/mokosh-grants", self.base_url);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", &self.basic_header)
            .query(&[(
                "owner_bunyip_user_id",
                owner_bunyip_user_id.to_string().as_str(),
            )])
            .send()
            .await
            .map_err(|e| AppError::internal(format!("bunyip mokosh-grant list transport: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                status = %status,
                body = %body.chars().take(200).collect::<String>(),
                "bunyip mokosh-grant list returned a non-2xx"
            );
            return Err(AppError::internal(format!(
                "bunyip mokosh-grant list returned status {status}"
            )));
        }

        // Response envelope mirrors bunyip's `success()`:
        // `{ "success": true, "data": [...], "meta": {...} }`.
        #[derive(Debug, Deserialize)]
        struct ListEnvelope {
            data: Option<Vec<OwnerGrantView>>,
        }
        let body: ListEnvelope = resp.json().await.map_err(|e| {
            AppError::internal(format!(
                "bunyip mokosh-grant list response was not JSON: {e}"
            ))
        })?;
        Ok(body.data.unwrap_or_default())
    }

    /// BUNYIP-748: change a bunyip grant's role in place. Same shape
    /// as `revoke_grant`: `Ok(())` on 2xx, `Err(AppError::Internal)`
    /// on transport / non-2xx (unknown id, foreign owner, revoked
    /// grant, or a role outside the PMS-1162 vocabulary all surface
    /// as non-2xx from bunyip). Distinguishing the cases is the
    /// caller upstream's job via the message body.
    ///
    /// The grantee's next request re-reads the mirror through
    /// `resolve_grantee_caller` and picks up the new role without
    /// re-authenticating; no session invalidation is needed.
    #[tracing::instrument(skip(self), fields(grant_id = %grant_id, owner = %owner_bunyip_user_id, role = %new_role))]
    pub async fn update_grant_role(
        &self,
        grant_id: Uuid,
        owner_bunyip_user_id: Uuid,
        new_role: &str,
    ) -> AppResult<()> {
        let url = format!("{}/v1/mokosh-grants/{grant_id}", self.base_url);
        let body = serde_json::json!({
            "owner_bunyip_user_id": owner_bunyip_user_id,
            "role": new_role,
        });
        let resp = self
            .http
            .patch(&url)
            .header("Authorization", &self.basic_header)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                AppError::internal(format!("bunyip mokosh-grant update transport: {e}"))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                status = %status,
                body = %body.chars().take(200).collect::<String>(),
                "bunyip mokosh-grant update returned a non-2xx"
            );
            return Err(AppError::internal(format!(
                "bunyip mokosh-grant update returned status {status}"
            )));
        }
        Ok(())
    }

    /// MAPPS-875: revoke a bunyip grant on the owner's behalf. Idempotent
    /// on bunyip's side (an already-revoked grant is 204 without
    /// re-firing the webhook), so retrying a network-dropped revoke is
    /// safe from mokosh's side. Returns `Ok(())` on 204; `Err` on
    /// transport / non-2xx / 404 (`grant not owned by this owner or
    /// unknown`).
    #[tracing::instrument(skip(self), fields(grant_id = %grant_id, owner = %owner_bunyip_user_id))]
    pub async fn revoke_grant(&self, grant_id: Uuid, owner_bunyip_user_id: Uuid) -> AppResult<()> {
        let url = format!("{}/v1/mokosh-grants/{grant_id}", self.base_url);
        let body = serde_json::json!({
            "owner_bunyip_user_id": owner_bunyip_user_id,
        });
        let resp = self
            .http
            .delete(&url)
            .header("Authorization", &self.basic_header)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                AppError::internal(format!("bunyip mokosh-grant revoke transport: {e}"))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                status = %status,
                body = %body.chars().take(200).collect::<String>(),
                "bunyip mokosh-grant revoke returned a non-2xx"
            );
            return Err(AppError::internal(format!(
                "bunyip mokosh-grant revoke returned status {status}"
            )));
        }
        Ok(())
    }

    /// Look one email up. Returns:
    /// - `Ok(Some(DirectoryHit { user_id, email_verified }))` on a
    ///   Bunyip match. Both fields matter: an unverified identity
    ///   is registered but the mokosh middleware still refuses to
    ///   JIT-provision it into someone else's tenant (PMS-1208
    ///   finding 7), so the caller has to distinguish "unknown" from
    ///   "known but unverified" to answer the owner accurately.
    /// - `Ok(None)` on 404 (unknown to Bunyip or soft-deleted).
    /// - `Err(AppError::Internal)` on transport failure or a non-2xx
    ///   non-404 response, so a Bunyip outage refuses the caller's
    ///   invitation rather than silently degrading to "create it
    ///   anyway."
    #[tracing::instrument(skip(self), fields(email = %redact(email)))]
    pub async fn lookup(&self, email: &str) -> AppResult<Option<DirectoryHit>> {
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
        let user_id = Uuid::parse_str(&data.user_id).map_err(|_| {
            AppError::internal(format!(
                "bunyip directory returned a non-UUID user_id: {}",
                data.user_id
            ))
        })?;
        Ok(Some(DirectoryHit {
            user_id,
            email_verified: data.email_verified,
        }))
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
