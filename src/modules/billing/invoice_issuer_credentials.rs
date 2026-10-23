//! MAPPS-1099 Phase 2d: OAuth 2.0 credential blobs for the delegated
//! invoice-issuer path.
//!
//! Each `SecretKind::Integration { provider }` row holds a JSON blob
//! carrying the OAuth 2.0 state a Phase 1b/1c client needs: the client
//! id + secret (deployment-owned), the current access + refresh
//! tokens, and the absolute expiry of the access token. Phase 2d's
//! dispatcher reads this blob, refreshes the access token when it is
//! near expiry, writes the new pair back, and hands a built
//! [`crate::modules::billing::provider_invoice::XeroCredentials`] or
//! [`crate::modules::billing::provider_invoice::QuickBooksCredentials`]
//! to the client.
//!
//! The blob is per-provider, because Xero's shape (bearer + tenant_id)
//! and QuickBooks's shape (bearer + realm_id, plus the separate
//! refresh-token-expiry Intuit returns) do not have a useful common
//! parent. One `enum IntegrationCredentialBlob` with per-provider
//! variants keeps a single `SecretKind::Integration` key per
//! (tenant, provider) and still has a typed shape at every call site.
//!
//! Rotation: Xero rotates the refresh token on every refresh, and
//! QuickBooks does the same AND rotates its own 100-day lifetime; the
//! saver here writes the new pair back BEFORE the issue call runs, so
//! a concurrent request through the next invoice sees the fresh
//! bearer. A refresh that fails `invalid_grant` lets the error
//! propagate through to the caller, which surfaces reconnect copy
//! (the Phase 1b/1c clients already classify this as
//! `AppError::Unauthorized`).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::modules::billing::invoice_issuer::InvoiceProviderKind;
use crate::modules::billing::provider_invoice::{
    QuickBooksCredentials, QuickBooksTokenResponse, XeroCredentials, XeroTokenResponse,
};
use crate::utils::error::{AppError, AppResult};

/// The JSON blob stored under `SecretKind::Integration { provider }`
/// for a delegated invoice-issuer connection. One variant per
/// provider; serialising as external-tagged JSON keeps the provider
/// discriminator in the stored value so a reader cannot confuse a
/// Xero blob for a QBO blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum IntegrationCredentialBlob {
    Xero(XeroBlob),
    Quickbooks(QuickbooksBlob),
}

/// Xero's stored OAuth state. `tenant_id` is Xero's own identifier for
/// the organisation the OAuth consent selected (stored on the
/// `integrations.external_organisation_id` column too; the one here
/// moves with the credential so a reader does not need both). The
/// absolute `access_token_expires_at` is written when the token
/// refresh landed; the near-expiry test is pure time comparison and
/// does not drift as the server sits idle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XeroBlob {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    pub access_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub tenant_id: String,
}

/// QuickBooks's stored OAuth state. QBO rotates the refresh token's
/// own 100-day lifetime on every refresh and returns
/// `x_refresh_token_expires_in`, so this blob carries both the
/// access-token expiry and the refresh-token expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickbooksBlob {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    pub access_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub realm_id: String,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
}

impl From<&XeroBlob> for XeroCredentials {
    fn from(b: &XeroBlob) -> Self {
        XeroCredentials {
            client_id: b.client_id.clone(),
            client_secret: b.client_secret.clone(),
            refresh_token: b.refresh_token.clone(),
            access_token: b.access_token.clone(),
            access_token_expires_at: b.access_token_expires_at,
            tenant_id: b.tenant_id.clone(),
        }
    }
}

impl From<&QuickbooksBlob> for QuickBooksCredentials {
    fn from(b: &QuickbooksBlob) -> Self {
        QuickBooksCredentials {
            client_id: b.client_id.clone(),
            client_secret: b.client_secret.clone(),
            refresh_token: b.refresh_token.clone(),
            access_token: b.access_token.clone(),
            access_token_expires_at: b.access_token_expires_at,
            realm_id: b.realm_id.clone(),
        }
    }
}

/// Deserialise a blob stored under `SecretKind::Integration` and
/// confirm it names the expected provider (so a Xero caller cannot
/// pick up a blob somebody wrote under the Xero key but tagged
/// `quickbooks`). Returns a classified `AppError::Unauthorized` when
/// the row is missing or malformed, which is the state admins see as
/// "reconnect this integration".
pub fn parse_blob(
    stored: Option<&str>,
    expected: InvoiceProviderKind,
) -> AppResult<IntegrationCredentialBlob> {
    let raw = stored.ok_or(AppError::Unauthorized)?;
    let blob: IntegrationCredentialBlob = serde_json::from_str(raw).map_err(|_| {
        tracing::warn!(
            provider = %expected.as_str(),
            "MAPPS-1099: stored integration credential did not parse; treating as unauthorized"
        );
        AppError::Unauthorized
    })?;
    match (&blob, expected) {
        (IntegrationCredentialBlob::Xero(_), InvoiceProviderKind::Xero)
        | (IntegrationCredentialBlob::Quickbooks(_), InvoiceProviderKind::Quickbooks) => Ok(blob),
        _ => {
            tracing::warn!(
                provider = %expected.as_str(),
                "MAPPS-1099: stored credential names a different provider than this call expects; \
                 the admin reconnected with the wrong integration"
            );
            Err(AppError::Unauthorized)
        }
    }
}

/// Apply a refreshed Xero token response to a stored blob. Overwrites
/// the access token and the rotated refresh token, and recomputes the
/// absolute expiry from `now + expires_in` (the one source of truth,
/// so a reader never has to decide between the response's
/// `expires_in` and the stored `access_token_expires_at`).
pub fn apply_xero_refresh(blob: &mut XeroBlob, response: &XeroTokenResponse, now: DateTime<Utc>) {
    blob.access_token = response.access_token.clone();
    blob.refresh_token = response.refresh_token.clone();
    blob.access_token_expires_at = now + Duration::seconds(response.expires_in.max(0));
}

/// Apply a refreshed QuickBooks token response to a stored blob.
/// Same shape as [`apply_xero_refresh`], with the extra step of
/// writing the refresh-token-expiry QBO returns.
pub fn apply_quickbooks_refresh(
    blob: &mut QuickbooksBlob,
    response: &QuickBooksTokenResponse,
    now: DateTime<Utc>,
) {
    blob.access_token = response.access_token.clone();
    blob.refresh_token = response.refresh_token.clone();
    blob.access_token_expires_at = now + Duration::seconds(response.expires_in.max(0));
    if let Some(seconds) = response.x_refresh_token_expires_in {
        blob.refresh_token_expires_at = Some(now + Duration::seconds(seconds.max(0)));
    }
}

/// Serialise a blob back to its stored string. Separate from
/// `IntegrationCredentialBlob::serialize` through serde because the
/// stored key is a `String` on the `SecretProvider` trait, so having a
/// named helper keeps the two-call sequence (`serialize` ->
/// `SecretProvider::put`) obvious at every rotation site.
pub fn serialize_blob(blob: &IntegrationCredentialBlob) -> AppResult<String> {
    serde_json::to_string(blob).map_err(|e| {
        AppError::internal(format!(
            "integration credential blob did not serialise: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(seconds: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(seconds, 0).unwrap()
    }

    #[test]
    fn blob_round_trips_through_serde() {
        let now = fixed(1_900_000_000);
        let xero = IntegrationCredentialBlob::Xero(XeroBlob {
            client_id: "cid".into(),
            client_secret: "csec".into(),
            refresh_token: "r1".into(),
            access_token: "a1".into(),
            access_token_expires_at: now,
            tenant_id: "xero-tenant".into(),
        });
        let raw = serialize_blob(&xero).unwrap();
        let parsed = parse_blob(Some(&raw), InvoiceProviderKind::Xero).unwrap();
        assert_eq!(parsed, xero);
    }

    #[test]
    fn parse_blob_refuses_a_blob_for_the_wrong_provider() {
        let xero = IntegrationCredentialBlob::Xero(XeroBlob {
            client_id: "cid".into(),
            client_secret: "csec".into(),
            refresh_token: "r".into(),
            access_token: "a".into(),
            access_token_expires_at: fixed(0),
            tenant_id: "t".into(),
        });
        let raw = serialize_blob(&xero).unwrap();
        let err = parse_blob(Some(&raw), InvoiceProviderKind::Quickbooks).unwrap_err();
        assert!(
            matches!(err, AppError::Unauthorized),
            "a Xero blob stored under what the caller thinks is a QBO key must refuse the issue: {err:?}"
        );
    }

    #[test]
    fn parse_blob_refuses_a_missing_or_malformed_row() {
        assert!(matches!(
            parse_blob(None, InvoiceProviderKind::Xero).unwrap_err(),
            AppError::Unauthorized
        ));
        assert!(matches!(
            parse_blob(Some("not json"), InvoiceProviderKind::Xero).unwrap_err(),
            AppError::Unauthorized
        ));
    }

    #[test]
    fn apply_xero_refresh_overwrites_both_tokens_and_bumps_the_expiry() {
        let now = fixed(1_900_000_000);
        let mut blob = XeroBlob {
            client_id: "cid".into(),
            client_secret: "csec".into(),
            refresh_token: "r-old".into(),
            access_token: "a-old".into(),
            access_token_expires_at: fixed(0),
            tenant_id: "t".into(),
        };
        apply_xero_refresh(
            &mut blob,
            &XeroTokenResponse {
                access_token: "a-new".into(),
                refresh_token: "r-new".into(),
                expires_in: 1800,
                token_type: Some("Bearer".into()),
                scope: None,
            },
            now,
        );
        assert_eq!(blob.access_token, "a-new");
        assert_eq!(blob.refresh_token, "r-new");
        assert_eq!(blob.access_token_expires_at, now + Duration::seconds(1800));
    }

    #[test]
    fn apply_quickbooks_refresh_also_bumps_the_refresh_token_expiry() {
        let now = fixed(1_900_000_000);
        let mut blob = QuickbooksBlob {
            client_id: "cid".into(),
            client_secret: "csec".into(),
            refresh_token: "r-old".into(),
            access_token: "a-old".into(),
            access_token_expires_at: fixed(0),
            realm_id: "123".into(),
            refresh_token_expires_at: None,
        };
        apply_quickbooks_refresh(
            &mut blob,
            &QuickBooksTokenResponse {
                access_token: "a-new".into(),
                refresh_token: "r-new".into(),
                expires_in: 3600,
                x_refresh_token_expires_in: Some(8_640_000),
                token_type: Some("bearer".into()),
            },
            now,
        );
        assert_eq!(blob.access_token, "a-new");
        assert_eq!(blob.refresh_token, "r-new");
        assert_eq!(blob.access_token_expires_at, now + Duration::seconds(3600));
        assert_eq!(
            blob.refresh_token_expires_at,
            Some(now + Duration::seconds(8_640_000))
        );
    }

    #[test]
    fn xero_blob_to_credentials_copies_every_field() {
        let blob = XeroBlob {
            client_id: "cid".into(),
            client_secret: "csec".into(),
            refresh_token: "r".into(),
            access_token: "a".into(),
            access_token_expires_at: fixed(123),
            tenant_id: "t".into(),
        };
        let creds: XeroCredentials = (&blob).into();
        assert_eq!(creds.client_id, blob.client_id);
        assert_eq!(creds.refresh_token, blob.refresh_token);
        assert_eq!(creds.tenant_id, blob.tenant_id);
    }

    #[test]
    fn quickbooks_blob_to_credentials_copies_every_field() {
        let blob = QuickbooksBlob {
            client_id: "cid".into(),
            client_secret: "csec".into(),
            refresh_token: "r".into(),
            access_token: "a".into(),
            access_token_expires_at: fixed(123),
            realm_id: "9130".into(),
            refresh_token_expires_at: None,
        };
        let creds: QuickBooksCredentials = (&blob).into();
        assert_eq!(creds.realm_id, blob.realm_id);
        assert_eq!(creds.access_token, blob.access_token);
    }
}
