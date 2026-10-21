//! MAPPS-1101: the host's Microsoft 365 Entra OAuth client, set from the
//! product.
//!
//! Deployment-wide, like [`super::google_client`] and [`super::email`]: one
//! Entra app registration per installation, effective for every tenant,
//! gated to the deployment's operator. Same shape as the Google pair: the
//! client lives in the declared app-secret provider, the write path hot-
//! swaps the live handle so a Connect that happens a second later uses
//! the new pair, and the view never returns either half.
//!
//! See [`super::google_client`] for the long docstring on why this is not
//! stored where the other settings are; the reasoning is identical for
//! Microsoft (it is two governed application-tier secrets, so it goes
//! through the `AppSecretProvider` seam, not `tenant_settings`).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::app_secrets::{AppSecrets, GovernedSecret};
use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::contact_sync::microsoft_oauth::{OauthClient, SharedMicrosoftClient};
use crate::modules::credential_move::move_value_with_readback;
use crate::modules::tenants::SYSTEM_TENANT_ID;
use crate::utils::error::{AppError, AppResult};

/// `PUT /settings/microsoft-contacts-client`.
///
/// Both halves, both required. An id and a secret have to come from the
/// same Entra app registration, so "change the secret and keep the id" is
/// the only partial case anyone would want and it is indistinguishable
/// from "paste the secret and forget the id".
#[derive(Debug, Deserialize)]
pub struct MicrosoftClientInput {
    pub client_id: String,
    pub client_secret: String,
}

/// `GET /settings/microsoft-contacts-client`. Names and booleans only.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MicrosoftClientView {
    pub client_id_set: bool,
    pub client_secret_set: bool,
    pub configured: bool,
    pub provider: &'static str,
    pub writable: bool,
    pub restart_required: bool,
}

impl MicrosoftClientView {
    pub fn of(secrets: &AppSecrets) -> Self {
        let declared = secrets.declared();
        let id_set = holds(secrets, GovernedSecret::MicrosoftContactsClientId);
        let secret_set = holds(secrets, GovernedSecret::MicrosoftContactsClientSecret);
        Self {
            client_id_set: id_set,
            client_secret_set: secret_set,
            configured: id_set && secret_set,
            provider: declared.as_str(),
            writable: secrets
                .provider(declared)
                .map(|provider| provider.is_writable())
                .unwrap_or(false),
            restart_required: false,
        }
    }
}

fn holds(secrets: &AppSecrets, secret: GovernedSecret) -> bool {
    secrets
        .get(secret)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

pub fn get_microsoft_client(secrets: &AppSecrets) -> MicrosoftClientView {
    MicrosoftClientView::of(secrets)
}

/// Write both halves, read them back, swap the live client. Same order
/// and reasoning as [`super::google_client::put_google_client`].
pub async fn put_microsoft_client(
    db: &Database,
    secrets: &Arc<AppSecrets>,
    live: &SharedMicrosoftClient,
    input: MicrosoftClientInput,
    ctx: &AuditCtx,
) -> AppResult<MicrosoftClientView> {
    let client_id = input.client_id.trim().to_string();
    let client_secret = input.client_secret.trim().to_string();
    validate(&client_id, &client_secret)?;

    let declared = secrets.declared();
    let provider = secrets.provider(declared).ok_or_else(|| {
        AppError::Configuration(format!(
            "The {declared} secret provider this deployment declares could not be built, so there \
             is nowhere to store the Microsoft client. Fix its configuration first; \
             `mokosh-server provider-status` reports which providers are reachable."
        ))
    })?;
    if !provider.is_writable() {
        return Err(AppError::validation_field(
            "client_id",
            format!(
                "cannot be stored: this deployment declares the {declared} secret provider, which \
                 the application cannot write, so set MICROSOFT_CONTACTS_CLIENT_ID_FILE and \
                 MICROSOFT_CONTACTS_CLIENT_SECRET_FILE, or point APP_SECRET_BACKEND at a provider \
                 that accepts writes"
            ),
        ));
    }

    let previously = MicrosoftClientView::of(secrets);
    write_pair_locked(live, provider.clone(), &client_id, &client_secret, declared).await?;

    let resolved = OauthClient::from_app_secrets(secrets.as_ref())?;
    live.swap(resolved);

    let view = MicrosoftClientView::of(secrets);
    let mut tx = db
        .begin_with_tenant(TenantId::from_trusted(SYSTEM_TENANT_ID))
        .await?;
    audit_write(
        &mut *tx,
        TenantId::from_trusted(SYSTEM_TENANT_ID),
        ctx,
        AuditAction::Update,
        "app_secrets",
        None,
        Some(serde_json::json!({
            "configured": previously.configured,
            "provider": previously.provider,
        })),
        Some(serde_json::json!({
            "event": "microsoft_contacts.client_set",
            "keys": [
                GovernedSecret::MicrosoftContactsClientId.name(),
                GovernedSecret::MicrosoftContactsClientSecret.name(),
            ],
            "provider": view.provider,
            "configured": view.configured,
            // Microsoft binds a refresh token to the client that issued it,
            // so a new id refuses every existing grant with `invalid_grant`
            // and each connection is asked to reconnect. The audit row is
            // where that shows up later.
            "replaced_a_configured_client": previously.configured,
        })),
    )
    .await?;
    tx.commit().await?;

    Ok(view)
}

/// Serialize two concurrent writes to the id/secret pair, same reasoning
/// as [`super::google_client::write_pair_locked`].
async fn write_pair_locked(
    live: &SharedMicrosoftClient,
    provider: Arc<dyn crate::app_secrets::AppSecretProvider>,
    client_id: &str,
    client_secret: &str,
    declared: crate::app_secrets::AppSecretProviderKind,
) -> AppResult<()> {
    let _write_guard = live.lock_write().await;
    for (secret, value) in [
        (GovernedSecret::MicrosoftContactsClientId, client_id),
        (GovernedSecret::MicrosoftContactsClientSecret, client_secret),
    ] {
        let target = provider.clone();
        let readback = provider.clone();
        move_value_with_readback(
            value,
            move |written| async move { target.set(secret, written).await },
            || async move { Ok(readback.get(secret)) },
        )
        .await
        .map_err(|e| {
            AppError::Configuration(format!(
                "Storing {secret} in the {declared} provider failed: {e}. The Microsoft client is \
                 unchanged if this was the first of the two, and half written if it was the \
                 second, which `mokosh-server provider-status` will show."
            ))
        })?;
    }
    Ok(())
}

/// Refuse a write that cannot be a working client.
///
/// Blank is refused because every provider treats a blank value as absent;
/// a swap is caught the same way the Google side catches it, by rejecting
/// a client_id that looks like a secret. Entra's client secret VALUE
/// character set is a Base64-ish opaque string; the ID is a GUID (36
/// chars, five hyphen-separated groups, hex). A GUID in the secret field
/// is likely a swap; a non-GUID in the id field is likely a swap too.
fn validate(client_id: &str, client_secret: &str) -> AppResult<()> {
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(AppError::validation_field(
            if client_id.is_empty() {
                "client_id"
            } else {
                "client_secret"
            },
            "is required, and so is the other half: an empty value reads as absent in every \
             provider, so half a pair cannot be stored",
        ));
    }
    if !looks_like_guid(client_id) {
        return Err(AppError::validation_field(
            "client_id",
            "is not shaped like an Entra client id (a GUID: 8-4-4-4-12 hex characters). The \
             two fields may be swapped, or you pasted an Object id instead of the Application \
             id. The Application (client) ID is the one Entra lists under App registrations",
        ));
    }
    if looks_like_guid(client_secret) {
        return Err(AppError::validation_field(
            "client_secret",
            "is shaped like a GUID, which is how Entra's client ids are shaped. The two fields \
             look swapped; the client secret VALUE (not its id) is an opaque Base64-ish string",
        ));
    }
    Ok(())
}

/// Whether `value` looks like an Entra client id (an RFC 4122 GUID in the
/// `8-4-4-4-12` hex layout). Case-insensitive, hyphens required.
fn looks_like_guid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        let want_hyphen = matches!(i, 8 | 13 | 18 | 23);
        if want_hyphen {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_or_swapped_pair_is_refused_by_name() {
        validate(
            "12345678-1234-1234-1234-123456789abc",
            "verylongopaquesecretvalue~.-",
        )
        .expect("a well shaped pair");

        let refusal = |id: &str, secret: &str| -> (String, String) {
            match validate(id, secret).expect_err("refused") {
                AppError::Validation { errors, .. } => {
                    let first = errors.first().expect("a field error").clone();
                    (first.field, first.message)
                }
                other => panic!("expected a field-level validation error, got {other}"),
            }
        };

        for (id, secret, field, expected) in [
            ("", "secret-value", "client_id", "is required"),
            (
                "12345678-1234-1234-1234-123456789abc",
                "",
                "client_secret",
                "is required",
            ),
            // Non-GUID in client_id field: a secret pasted in the id slot.
            (
                "verylongopaquesecretvalue~.-",
                "12345678-1234-1234-1234-123456789abc",
                "client_id",
                "GUID",
            ),
            // GUID in the client_secret field: an id pasted in the secret slot.
            (
                "12345678-1234-1234-1234-123456789abc",
                "87654321-abcd-abcd-abcd-abcdef012345",
                "client_secret",
                "swapped",
            ),
        ] {
            let (got_field, message) = refusal(id, secret);
            assert_eq!(
                got_field, field,
                "the error names the wrong field: {message}"
            );
            assert!(
                message.contains(expected),
                "expected {expected:?} in {message}"
            );
        }
    }

    #[test]
    fn looks_like_guid_matches_the_entra_shape() {
        assert!(looks_like_guid("12345678-1234-1234-1234-123456789abc"));
        assert!(looks_like_guid("ABCDEF01-ABCD-ABCD-ABCD-ABCDEF012345"));
        assert!(!looks_like_guid("12345678-1234-1234-1234-123456789"));
        assert!(!looks_like_guid("12345678-1234-1234-1234-123456789abcd"));
        assert!(!looks_like_guid("not-a-guid-at-all"));
        assert!(!looks_like_guid(""));
        assert!(!looks_like_guid(
            "12345678g1234h1234i1234j123456789abc"
        ));
    }

    #[test]
    fn the_view_never_carries_a_value() {
        use crate::app_secrets::{AppSecretProvider, AppSecretProviderKind};
        use async_trait::async_trait;

        struct Held;
        #[async_trait]
        impl AppSecretProvider for Held {
            fn name(&self) -> &'static str {
                "database"
            }
            fn get(&self, secret: GovernedSecret) -> Option<String> {
                Some(match secret {
                    GovernedSecret::MicrosoftContactsClientId => {
                        "11111111-2222-3333-4444-555555555555".to_string()
                    }
                    GovernedSecret::MicrosoftContactsClientSecret => {
                        "LeakyBeakyMicrosoftSecret".to_string()
                    }
                    _ => return None,
                })
            }
        }

        let secrets = AppSecrets::with_provider(AppSecretProviderKind::Database, Arc::new(Held));
        let view = get_microsoft_client(&secrets);
        assert!(view.client_id_set);
        assert!(view.client_secret_set);
        assert!(view.configured);
        let json = serde_json::to_string(&view).expect("the view serialises");
        assert!(
            !json.contains("11111111") && !json.contains("LeakyBeaky"),
            "the view carries a credential: {json}"
        );
    }

    #[test]
    fn a_half_or_empty_deployment_is_not_configured() {
        use crate::app_secrets::{AppSecretProvider, AppSecretProviderKind};
        use async_trait::async_trait;

        struct OnlyId;
        #[async_trait]
        impl AppSecretProvider for OnlyId {
            fn name(&self) -> &'static str {
                "database"
            }
            fn get(&self, secret: GovernedSecret) -> Option<String> {
                match secret {
                    GovernedSecret::MicrosoftContactsClientId => {
                        Some("11111111-2222-3333-4444-555555555555".to_string())
                    }
                    _ => None,
                }
            }
        }

        let half = AppSecrets::with_provider(AppSecretProviderKind::Database, Arc::new(OnlyId));
        let view = get_microsoft_client(&half);
        assert!(view.client_id_set);
        assert!(!view.client_secret_set);
        assert!(
            !view.configured,
            "half a pair is a boot error, never a configured deployment"
        );
    }
}
