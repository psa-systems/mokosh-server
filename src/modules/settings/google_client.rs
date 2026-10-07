//! PMS-1444: the host's Google OAuth client, set from the product.
//!
//! Deployment-wide, like [`super::email`] and [`super::app_name`]: one Google
//! application per installation, effective for every tenant, gated to the
//! deployment's operator. It is the same tier of setting as the SMTP relay and
//! it is deliberately built in the same shape, down to the write-only secret and
//! the swap that makes a write take effect without a restart (PMS-638).
//!
//! ## Why this is not stored where the other settings are
//!
//! `email` and `app_name` keep their values in `tenant_settings` on the system
//! tenant. This pair does not: it is two governed application-tier secrets
//! (`src/app_secrets/`), so it goes through whichever `AppSecretProvider` the
//! deployment declared, which may be Postgres, Infisical, a file or
//! `{NAME}_FILE`. Writing it to `tenant_settings` would put a live Google client
//! secret in a table the storage seam does not govern and would be invisible to
//! the boot survey that classifies it, which is the whole apparatus PMS-988
//! built for exactly this value.
//!
//! PMS-1430 removed a per-tenant form that wrote a client to `tenant_settings`,
//! and migration 258 deleted the rows it left. This is not that form returning:
//! the tier, the audience and the store are all different.
//!
//! ## What it will not do
//!
//! Return either half. Not the secret, obviously, and not the id either. The id
//! is not secret, but an endpoint that returns it invites a page that displays
//! it, and then a support conversation about which project it belongs to, and
//! the honest answer to "is this deployment configured" is a boolean.
//! [`crate::app_secrets::AppSecretsStatus`] already exists for that shape.
//!
//! Write one half. A host holding one half is a boot error by design
//! (`OauthClient::from_app_secrets`), so an API that could create that state
//! would be an API for breaking the next restart.
//!
//! Write to a provider the deployment did not declare. That is `Misplaced`,
//! which is fatal at boot. It is also why this refuses rather than falls back
//! when the declared provider cannot be written: the `environment` provider
//! reads `{NAME}_FILE` and a process cannot set a variable for its own next
//! boot, so the operator is told that instead of being lied to.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::app_secrets::{AppSecrets, GovernedSecret};
use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::contact_sync::{OauthClient, SharedGoogleClient};
use crate::modules::credential_move::move_value_with_readback;
use crate::modules::tenants::SYSTEM_TENANT_ID;
use crate::utils::error::{AppError, AppResult};

/// The shape a Google client id has, used only to catch the two fields being
/// swapped.
const ID_SUFFIX: &str = ".apps.googleusercontent.com";

/// The prefix Google gives a client secret, same purpose.
const SECRET_PREFIX: &str = "GOCSPX-";

/// `PUT /settings/google-contacts-client`.
///
/// Both halves, both required. Unlike [`super::email::EmailSettingsInput`],
/// where a `None` field keeps its stored value, there is no partial write here:
/// an id and a secret have to come from the same Google project, so "change the
/// secret and keep the id" is the only partial case anyone would want and it is
/// indistinguishable from "paste the secret and forget the id".
#[derive(Debug, Deserialize)]
pub struct GoogleClientInput {
    pub client_id: String,
    pub client_secret: String,
}

/// `GET /settings/google-contacts-client`. Names and booleans only.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GoogleClientView {
    /// Whether the declared provider holds the id.
    pub client_id_set: bool,
    /// Whether the declared provider holds the secret.
    pub client_secret_set: bool,
    /// Both halves present, so the deployment can actually connect. Not
    /// `client_id_set && client_secret_set` for the reader to work out: this is
    /// the question the Settings card asks and it should not be reassembled at
    /// each caller.
    pub configured: bool,
    /// Which provider serves the pair, for an operator diagnosing a deployment
    /// whose values are somewhere else.
    pub provider: &'static str,
    /// Whether this process can write that provider. `false` means the form is
    /// read-only on this deployment and the operator has to use the file or
    /// environment route.
    pub writable: bool,
    /// Whether a write needs a restart to take effect. `false` here because the
    /// write path swaps the live handle; it is a field rather than an omission
    /// so a client can stop promising immediacy if that ever changes.
    pub restart_required: bool,
}

impl GoogleClientView {
    pub fn of(secrets: &AppSecrets) -> Self {
        let declared = secrets.declared();
        let id_set = holds(secrets, GovernedSecret::GoogleContactsClientId);
        let secret_set = holds(secrets, GovernedSecret::GoogleContactsClientSecret);
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

/// Whether the declared provider holds a non-blank value for `secret`.
///
/// Through `AppSecrets::get`, which reads the declared provider only. A value
/// in another provider is not "set" for this purpose: it is the `Misplaced`
/// state, and reporting it as set would tell an operator the deployment is
/// configured while the next boot refuses to start.
fn holds(secrets: &AppSecrets, secret: GovernedSecret) -> bool {
    secrets
        .get(secret)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

pub fn get_google_client(secrets: &AppSecrets) -> GoogleClientView {
    GoogleClientView::of(secrets)
}

/// Write both halves, read them back, then swap the client the running process
/// uses.
///
/// The order matters and is the same order [`super::email::put_email_settings`]
/// plus `rebuild_and_swap` follow: persist first, then make it live. A swap that
/// ran first would leave a process using a client that is not stored, so a
/// restart would silently revert it.
///
/// The swap re-reads through [`OauthClient::from_app_secrets`] rather than
/// building the client from the input. It costs nothing and it means the live
/// value is the stored value by construction: if the provider normalised,
/// truncated or refused a half, the process does not carry a client the next
/// boot will not agree with.
pub async fn put_google_client(
    db: &Database,
    secrets: &Arc<AppSecrets>,
    live: &SharedGoogleClient,
    input: GoogleClientInput,
    ctx: &AuditCtx,
) -> AppResult<GoogleClientView> {
    let client_id = input.client_id.trim().to_string();
    let client_secret = input.client_secret.trim().to_string();
    validate(&client_id, &client_secret)?;

    let declared = secrets.declared();
    let provider = secrets.provider(declared).ok_or_else(|| {
        AppError::Configuration(format!(
            "The {declared} secret provider this deployment declares could not be built, so there \
             is nowhere to store the Google client. Fix its configuration first; \
             `mokosh-server provider-status` reports which providers are reachable."
        ))
    })?;
    if !provider.is_writable() {
        return Err(AppError::validation_field(
            "client_id",
            format!(
                "cannot be stored: this deployment declares the {declared} secret provider, which \
                 the application cannot write, so set GOOGLE_CONTACTS_CLIENT_ID_FILE and \
                 GOOGLE_CONTACTS_CLIENT_SECRET_FILE, or point APP_SECRET_BACKEND at a provider that \
                 accepts writes"
            ),
        ));
    }

    let previously = GoogleClientView::of(secrets);
    write_pair_locked(live, provider.clone(), &client_id, &client_secret, declared).await?;

    // Live before audit, so a failing audit write cannot leave the process
    // serving a client the operator was told did not save.
    let resolved = OauthClient::from_app_secrets(secrets.as_ref())?;
    live.swap(resolved);

    let view = GoogleClientView::of(secrets);
    // SAFETY (PMS-285): a deployment-wide write addressed to the system tenant,
    // the same scope `settings::email` writes and the documented
    // `from_trusted` case for an operator handler that is not acting as a
    // member of a tenant.
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
            "event": "google_contacts.client_set",
            "keys": [
                GovernedSecret::GoogleContactsClientId.name(),
                GovernedSecret::GoogleContactsClientSecret.name(),
            ],
            "provider": view.provider,
            "configured": view.configured,
            // PMS-1430: Google binds a refresh token to the client that issued
            // it, so a new id refuses every existing grant with
            // `invalid_grant` and each connection is asked to reconnect. The
            // audit row is where that shows up later, when somebody asks why
            // every tenant disconnected on a Tuesday.
            "replaced_a_configured_client": previously.configured,
        })),
    )
    .await?;
    tx.commit().await?;

    Ok(view)
}

/// Write the id then the secret, with both writes serialized against any
/// other concurrent caller of this same setting.
///
/// PMS-1473: `live.lock_write()` is held across both
/// [`move_value_with_readback`] calls, not just one, so a second concurrent
/// `PUT` either waits here for the first request's id-and-secret pair to
/// finish together, or runs fully after it. Without the lock, two requests'
/// writes could interleave key by key and leave the provider holding one
/// caller's id paired with the other's secret, which Google rejects as
/// `invalid_client` on every later contact-sync attempt.
async fn write_pair_locked(
    live: &SharedGoogleClient,
    provider: Arc<dyn crate::app_secrets::AppSecretProvider>,
    client_id: &str,
    client_secret: &str,
    declared: crate::app_secrets::AppSecretProviderKind,
) -> AppResult<()> {
    let _write_guard = live.lock_write().await;
    for (secret, value) in [
        (GovernedSecret::GoogleContactsClientId, client_id),
        (GovernedSecret::GoogleContactsClientSecret, client_secret),
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
                "Storing {secret} in the {declared} provider failed: {e}. The Google client is \
                 unchanged if this was the first of the two, and half written if it was the \
                 second, which `mokosh-server provider-status` will show."
            ))
        })?;
    }
    Ok(())
}

/// Refuse a write that cannot be a working client.
///
/// Blank is refused because every provider treats a blank value as absent, so
/// storing one reports success and leaves the feature off. The swap check is the
/// interesting one: pasting the secret into the id field and the id into the
/// secret field is the single most likely mistake on a two-field form whose
/// values are both long opaque strings, and it fails at Google with
/// `invalid_client`, which names neither field. Recognised by Google's own
/// affixes rather than by validating the id's whole format, so a future change
/// to that format cannot lock an operator out of this form.
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
    if client_id.starts_with(SECRET_PREFIX) {
        return Err(AppError::validation_field(
            "client_id",
            format!(
                "starts with {SECRET_PREFIX}, which is how Google's client secrets begin, so the \
                 two fields look swapped"
            ),
        ));
    }
    if client_secret.ends_with(ID_SUFFIX) {
        return Err(AppError::validation_field(
            "client_secret",
            format!(
                "ends with {ID_SUFFIX}, which is how Google's client ids end, so the two fields \
                 look swapped"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both halves required, and a swapped pair is named as swapped.
    ///
    /// The swap case is the reason this function exists. Both values are long
    /// opaque strings on a two-field form, and Google's answer to a swapped
    /// pair is `invalid_client`, which does not say which field is wrong.
    ///
    /// Asserted against the FIELD errors rather than `to_string()`, because
    /// `AppError::Validation`'s `Display` is the generic "one or more fields
    /// are invalid" and the sentence an operator reads is the per-field one.
    /// The field name is asserted too: a message on the wrong field points the
    /// form's error at the box that was right.
    #[test]
    fn a_blank_or_swapped_pair_is_refused_by_name() {
        validate("x.apps.googleusercontent.com", "GOCSPX-fine").expect("a well shaped pair");

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
            ("", "GOCSPX-fine", "client_id", "is required"),
            (
                "x.apps.googleusercontent.com",
                "",
                "client_secret",
                "is required",
            ),
            (
                "GOCSPX-secret-in-the-id-field",
                "x.apps.googleusercontent.com",
                "client_id",
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
            assert!(
                !message.contains("secret-in-the-id-field"),
                "the value leaked into the refusal: {message}"
            );
        }
    }

    /// A secret that merely CONTAINS the id suffix is not a swap.
    ///
    /// Google's secrets are opaque, so a substring match would refuse a valid
    /// one. Anchored at the ends, where the affixes actually are.
    #[test]
    fn the_swap_check_is_anchored_and_not_a_substring_match() {
        validate(
            "x.apps.googleusercontent.com",
            "GOCSPX-.apps.googleusercontent.com-tail",
        )
        .expect("the affixes are anchored, so this is not a swap");
    }

    /// The view carries names and booleans, and no value can reach it.
    ///
    /// Scanned as a serialisation rather than asserted field by field, because
    /// what matters is that nothing a provider returned appears in the JSON a
    /// client receives. A field added later that carried a value would fail
    /// here without anyone remembering this rule.
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
                    GovernedSecret::GoogleContactsClientId => {
                        "pms1444.apps.googleusercontent.com".to_string()
                    }
                    GovernedSecret::GoogleContactsClientSecret => {
                        "GOCSPX-pms1444-secret".to_string()
                    }
                    GovernedSecret::SmtpPassword => "smtp".to_string(),
                })
            }
        }

        let secrets = AppSecrets::with_provider(AppSecretProviderKind::Database, Arc::new(Held));
        let view = get_google_client(&secrets);
        assert_eq!(
            view,
            GoogleClientView {
                client_id_set: true,
                client_secret_set: true,
                configured: true,
                provider: "database",
                writable: true,
                restart_required: false,
            }
        );
        let json = serde_json::to_string(&view).expect("the view serialises");
        assert!(
            !json.contains("pms1444") && !json.contains("GOCSPX"),
            "the view carries a credential: {json}"
        );
    }

    /// A deployment holding neither half reports unconfigured rather than
    /// erroring, and one holding the id alone is NOT reported as configured.
    ///
    /// The second half of that is the one worth pinning. A half-configured host
    /// refuses to boot, so a view that called it configured would tell an
    /// operator the deployment is fine right up until the next restart.
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
                    GovernedSecret::GoogleContactsClientId => {
                        Some("only.apps.googleusercontent.com".to_string())
                    }
                    _ => None,
                }
            }
        }

        let half = AppSecrets::with_provider(AppSecretProviderKind::Database, Arc::new(OnlyId));
        let view = get_google_client(&half);
        assert!(view.client_id_set);
        assert!(!view.client_secret_set);
        assert!(
            !view.configured,
            "half a pair is a boot error, never a configured deployment"
        );
    }

    /// PMS-1473: two concurrent writers cannot leave the provider holding a
    /// mismatched id/secret pair.
    ///
    /// The fake provider sleeps right after storing the id and before
    /// `write_pair_locked` moves on to the secret, the exact window the bug
    /// report interleaves in: without `live.lock_write()`, both callers could
    /// write their ids, then both write their secrets in whatever order,
    /// landing one caller's id next to the other's secret. With the lock,
    /// one caller's full id-then-secret pair always finishes before the
    /// other's starts.
    #[tokio::test]
    async fn concurrent_writes_are_serialized_not_interleaved() {
        use crate::app_secrets::{AppSecretProvider, AppSecretProviderKind};
        use async_trait::async_trait;
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;

        struct DelayedStore {
            id: StdMutex<Option<String>>,
            secret: StdMutex<Option<String>>,
        }

        #[async_trait]
        impl AppSecretProvider for DelayedStore {
            fn name(&self) -> &'static str {
                "database"
            }
            fn get(&self, secret: GovernedSecret) -> Option<String> {
                match secret {
                    GovernedSecret::GoogleContactsClientId => self.id.lock().unwrap().clone(),
                    GovernedSecret::GoogleContactsClientSecret => {
                        self.secret.lock().unwrap().clone()
                    }
                    GovernedSecret::SmtpPassword => None,
                }
            }
            async fn set(&self, secret: GovernedSecret, value: &str) -> AppResult<()> {
                match secret {
                    GovernedSecret::GoogleContactsClientId => {
                        *self.id.lock().unwrap() = Some(value.to_string());
                        // The interleaving window: give a concurrent caller a
                        // chance to run between this caller's id write and its
                        // secret write.
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    GovernedSecret::GoogleContactsClientSecret => {
                        *self.secret.lock().unwrap() = Some(value.to_string());
                    }
                    GovernedSecret::SmtpPassword => {}
                }
                Ok(())
            }
        }

        let provider: Arc<dyn AppSecretProvider> = Arc::new(DelayedStore {
            id: StdMutex::new(None),
            secret: StdMutex::new(None),
        });
        let live = SharedGoogleClient::default();

        let a = write_pair_locked(
            &live,
            provider.clone(),
            "a.apps.googleusercontent.com",
            "GOCSPX-a-secret",
            AppSecretProviderKind::Database,
        );
        let b = write_pair_locked(
            &live,
            provider.clone(),
            "b.apps.googleusercontent.com",
            "GOCSPX-b-secret",
            AppSecretProviderKind::Database,
        );
        let (a_result, b_result) = tokio::join!(a, b);
        a_result.expect("a's write must succeed");
        b_result.expect("b's write must succeed");

        let id = provider
            .get(GovernedSecret::GoogleContactsClientId)
            .expect("id stored");
        let secret = provider
            .get(GovernedSecret::GoogleContactsClientSecret)
            .expect("secret stored");
        let matches_a = id == "a.apps.googleusercontent.com" && secret == "GOCSPX-a-secret";
        let matches_b = id == "b.apps.googleusercontent.com" && secret == "GOCSPX-b-secret";
        assert!(
            matches_a || matches_b,
            "stored pair is a mix of two callers: id={id}, secret={secret}"
        );
    }
}
