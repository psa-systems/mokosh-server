//! MAPPS-1142: connecting a tenant's Xero organisation or QuickBooks
//! company file.
//!
//! The round trip everything else in MAPPS-1099 was waiting on. The
//! clients issue, the dispatcher routes and the receivers listen, and
//! until this existed nothing wrote the credential blob all three read.
//!
//! The shape is contact sync's, twice over (PSA-70 for Google, MAPPS-1101
//! for Microsoft 365), deliberately: a second shape for one problem is a
//! second thing to reason about. Mint a single-use state, send the admin
//! to the provider, verify and CONSUME the state when they come back,
//! exchange the code, write what came back, redirect.
//!
//! # What the two providers do not share
//!
//! QuickBooks puts `realmId` on the callback, so the company file is known
//! without asking. Xero's token response says nothing about which
//! organisation was authorized, so the exchange is followed by
//! `GET /connections`.
//!
//! A Xero grant covering several organisations is refused rather than
//! guessed at. Picking one would delegate a tenant's invoicing to an
//! organisation nobody chose, and there is nowhere to put the others:
//! `integrations` is UNIQUE on `(tenant_id, provider)`.

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::modules::billing::invoice_issuer::InvoiceProviderKind;
use crate::modules::billing::invoice_issuer_app::IssuerApps;
use crate::modules::billing::invoice_issuer_credentials::{
    serialize_blob, IntegrationCredentialBlob, QuickbooksBlob, XeroBlob,
};
use crate::modules::billing::provider_invoice::{QuickBooksClient, XeroClient};
use crate::modules::contact_sync::oauth::Pkce;
use crate::secrets::{SecretKey, SecretProvider};
use crate::utils::crypto::{generate_token, hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};
use mokosh_types::integrations::{Capability, IntegrationStatus};

use std::sync::Arc;

/// How long a consent screen may sit open. Ten minutes is longer than
/// choosing an organisation takes and far shorter than a tab left open
/// overnight, which is the window a stolen state would be replayed in.
/// The same number contact sync uses, for the same reason.
const STATE_TTL_MINUTES: i64 = 10;

/// The two consent endpoints.
///
/// Assembled from parts until MAPPS-1153, for the reason the clients'
/// hosts were: `built_providers_have_something_behind_them` (MAPPS-1121)
/// scans `src/modules` for a provider's real host and fails when it finds
/// one behind a descriptor still marked `Planned`. Both descriptors are
/// `Built` now - the page that drives this flow exists, and
/// `credential_home` moved with the flip so Connected Services links to
/// that page instead of offering a credential box.
fn xero_auth_endpoint() -> String {
    "https://login.xero.com/identity/connect/authorize".to_string()
}

fn quickbooks_auth_endpoint() -> String {
    "https://appcenter.intuit.com/connect/oauth2".to_string()
}

/// What Mokosh asks each provider for.
///
/// `offline_access` is what makes a refresh token come back, and without
/// one a connection lasts an hour. The rest is the narrowest set that lets
/// an invoice be created and read back: Xero needs contacts to address one
/// and transactions to create one, Intuit's accounting scope is not
/// divisible.
const XERO_SCOPES: &str = "offline_access accounting.transactions accounting.contacts";
const QUICKBOOKS_SCOPES: &str = "com.intuit.quickbooks.accounting";

#[derive(Clone)]
pub struct InvoiceIssuerConnectService {
    db: Database,
    secrets: Arc<dyn SecretProvider>,
    apps: Arc<IssuerApps>,
    /// The deployment's feature toggles (MAPPS-1154).
    ///
    /// Held so the settings card can say whether delegated issuing is
    /// switched ON for this deployment. The connect flow itself does not
    /// gate on it: connecting first and switching on afterwards is a
    /// reasonable order to do things in, and refusing the connect would
    /// leave an operator unable to prepare a tenant before the flip.
    features: crate::modules::features::FeatureSnapshot,
    xero: Arc<XeroClient>,
    quickbooks: Arc<QuickBooksClient>,
    /// Where the provider returns the browser to. `None` is a deployment
    /// with no public base, which cannot complete a round trip and says so
    /// rather than building a URL that goes nowhere.
    public_api_base: Option<String>,
    /// Where the admin is sent afterwards.
    app_base: String,
}

impl InvoiceIssuerConnectService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Database,
        secrets: Arc<dyn SecretProvider>,
        apps: Arc<IssuerApps>,
        features: crate::modules::features::FeatureSnapshot,
        xero: Arc<XeroClient>,
        quickbooks: Arc<QuickBooksClient>,
        public_api_base: Option<String>,
        app_base: String,
    ) -> Self {
        Self {
            db,
            secrets,
            apps,
            features,
            xero,
            quickbooks,
            public_api_base,
            app_base,
        }
    }

    /// The address the provider returns the browser to.
    pub fn redirect_uri(&self, provider: InvoiceProviderKind) -> AppResult<String> {
        let base = self
            .public_api_base
            .as_deref()
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| {
                AppError::Configuration(format!(
                    "PUBLIC_API_BASE_URL is not set, so {} has no address to return to.",
                    provider.as_str()
                ))
            })?;
        Ok(format!(
            "{}/api/v1/public/invoice-issuer/{}/callback",
            base.trim_end_matches('/'),
            provider.as_str()
        ))
    }

    /// Start a connection: mint the state, answer the consent URL.
    pub async fn begin(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        provider: InvoiceProviderKind,
    ) -> AppResult<String> {
        // A deployment with no application for this provider has nothing to
        // authorize against, and the refusal names the deployment rather
        // than the tenant.
        let app = self.apps.require(provider)?;
        let redirect_uri = self.redirect_uri(provider)?;
        let pkce = Pkce::generate();
        let secret = generate_token(48);
        let state_hash = hash_password(&secret).await?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let state_id: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice_issuer_oauth_states \
             (tenant_id, provider, started_by_user_id, state_hash, code_verifier, redirect_uri, \
              expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(user_id)
        .bind(&state_hash)
        .bind(&pkce.verifier)
        .bind(&redirect_uri)
        .bind(Utc::now() + Duration::minutes(STATE_TTL_MINUTES))
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        let state = format!("{state_id}.{secret}");
        Ok(authorization_url(
            provider,
            &app.client_id,
            &redirect_uri,
            &state,
            &pkce,
        ))
    }

    /// Finish a connection.
    ///
    /// SAFETY (PMS-285): runs with no session, so the tenant comes from the
    /// state row the caller proved possession of, and every write after
    /// that is scoped to it. `realm_id` is Intuit's and is ignored for
    /// Xero, whose organisation is asked for instead.
    pub async fn complete(
        &self,
        provider: InvoiceProviderKind,
        state: &str,
        code: &str,
        realm_id: Option<&str>,
    ) -> AppResult<String> {
        let (tenant_uuid, code_verifier, redirect_uri) =
            self.consume_state(provider, state).await?;
        let tenant_id = TenantId::from_trusted(tenant_uuid);
        let app = self.apps.require(provider)?;

        let (blob, organisation_id) = match provider {
            InvoiceProviderKind::Xero => {
                let tokens = self
                    .xero
                    .exchange_code(
                        &app.client_id,
                        &app.client_secret,
                        &redirect_uri,
                        code,
                        &code_verifier,
                    )
                    .await?;
                let connections = self.xero.list_connections(&tokens.access_token).await?;
                let organisation = match connections.as_slice() {
                    [one] => one.tenant_id.clone(),
                    [] => {
                        return Err(AppError::BadRequest(
                            "That Xero sign-in authorised no organisation. Start again from \
                             Settings and choose the organisation to invoice from."
                                .to_string(),
                        ))
                    }
                    several => {
                        // Not a guess: picking one would delegate this
                        // tenant's invoicing to an organisation nobody
                        // chose, and `integrations` holds one row per
                        // provider so the others have nowhere to go.
                        return Err(AppError::BadRequest(format!(
                            "That Xero sign-in authorised {} organisations. Start again from \
                             Settings and authorise the one Mokosh should invoice from.",
                            several.len()
                        )));
                    }
                };
                let blob = IntegrationCredentialBlob::Xero(XeroBlob {
                    refresh_token: tokens.refresh_token,
                    access_token: tokens.access_token,
                    access_token_expires_at: Utc::now() + Duration::seconds(tokens.expires_in),
                    tenant_id: organisation.clone(),
                });
                (blob, organisation)
            }
            InvoiceProviderKind::Quickbooks => {
                let realm = realm_id
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                    .ok_or_else(|| {
                        AppError::BadRequest(
                            "That QuickBooks sign-in named no company. Start again from Settings."
                                .to_string(),
                        )
                    })?
                    .to_string();
                let tokens = self
                    .quickbooks
                    .exchange_code(
                        &app.client_id,
                        &app.client_secret,
                        &redirect_uri,
                        code,
                        &code_verifier,
                    )
                    .await?;
                let blob = IntegrationCredentialBlob::Quickbooks(QuickbooksBlob {
                    refresh_token: tokens.refresh_token,
                    access_token: tokens.access_token,
                    access_token_expires_at: Utc::now() + Duration::seconds(tokens.expires_in),
                    realm_id: realm.clone(),
                    refresh_token_expires_at: tokens
                        .x_refresh_token_expires_in
                        .map(|s| Utc::now() + Duration::seconds(s)),
                });
                (blob, realm)
            }
        };

        self.secrets
            .put(
                &SecretKey::integration(*tenant_id, provider.as_str()),
                &serialize_blob(&blob)?,
            )
            .await?;
        self.record_connection(tenant_id, provider, &organisation_id)
            .await?;

        Ok(format!(
            "{}/settings/integrations",
            self.app_base.trim_end_matches('/')
        ))
    }

    /// Stop delegating to a provider, and forget how to reach it
    /// (MAPPS-1145).
    ///
    /// The credential goes, because the blob is what every delegated call
    /// reads and a disconnect that left it behind would leave a working
    /// connection the UI says is off.
    ///
    /// The capability set stays. That is the house rule for `disconnected`
    /// (PMS-1312, and the reason the four statuses are not a boolean):
    /// what a tenant delegated is their answer, and reconnecting should not
    /// start from an empty page. It is safe to keep only because
    /// `IssuerDispatcher::plan` requires a LIVE connection as well as the
    /// capability; before MAPPS-1145 it read the capability alone, and a
    /// row in this state would have sent every new invoice down a
    /// delegated path whose credential had just been deleted.
    pub async fn disconnect(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
    ) -> AppResult<()> {
        self.secrets
            .delete(&SecretKey::integration(*tenant_id, provider.as_str()))
            .await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE integrations \
             SET status = 'disconnected', disconnected_at = NOW(), last_error = NULL, \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delegate, or stop delegating, this tenant's bills to the provider
    /// (MAPPS-1155).
    ///
    /// `record_connection` writes `{invoicing}` because connecting through
    /// that flow IS the invoice delegation. Bills are a second decision in
    /// the other direction (what the MSP owes, not what it is owed), so
    /// they are a toggle on the connected row rather than part of
    /// consenting, and nothing else can set the capability: without this
    /// the dispatcher's bill half would be unreachable on every
    /// deployment, which is the "advertises what the build cannot deliver"
    /// defect MAPPS-1155 exists to close.
    ///
    /// Refused unless the row is connected: a capability on a provider
    /// with no credentials is an arrangement nothing can honour.
    pub async fn set_bills_delegation(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        enabled: bool,
    ) -> AppResult<()> {
        let bills = Capability::BillsAndExpenses.as_str();
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String, Vec<String>)> = sqlx::query_as(
            "SELECT status, enabled_capabilities FROM integrations \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let Some((status, capabilities)) = row else {
            return Err(AppError::Conflict(format!(
                "Connect {} before delegating bills to it.",
                provider.as_str()
            )));
        };
        if status != IntegrationStatus::Connected.as_str() {
            return Err(AppError::Conflict(format!(
                "{} is not connected, so bills cannot be delegated to it.",
                provider.as_str()
            )));
        }
        let mut next: Vec<String> = capabilities.into_iter().filter(|c| c != bills).collect();
        if enabled {
            next.push(bills.to_string());
        }
        sqlx::query(
            "UPDATE integrations SET enabled_capabilities = $3, updated_at = NOW() \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(&next)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// What a settings page for one provider reads (MAPPS-1143).
    ///
    /// Four facts, and three of them the integrations catalog cannot
    /// express. `configured` is the deployment's, not the tenant's, and is
    /// the whole answer a tenant gets about the application (PMS-1430: the
    /// client is the host's and there is nothing for a tenant to edit).
    /// `organisation_id` is how an admin with two Xero organisations tells
    /// a right connection from a wrong one. `delegated` is whether
    /// `invoicing` is actually enabled, which the OAuth flow sets and
    /// nothing else does.
    pub async fn overview(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
    ) -> AppResult<InvoiceIssuerOverview> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<OverviewRow> = sqlx::query_as(
            "SELECT status, enabled_capabilities, external_organisation_id, last_error \
             FROM integrations WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        let configured = self.apps.get(provider).is_some();
        let delegation_enabled = self
            .features
            .is_enabled(crate::modules::features::Feature::DelegatedInvoiceIssuer);
        let bills_delegation_enabled = self
            .features
            .is_enabled(crate::modules::features::Feature::DelegatedBills);
        let Some(row) = row else {
            // Never connected is an offer, not an error.
            return Ok(InvoiceIssuerOverview {
                provider: provider.as_str().to_string(),
                configured,
                status: IntegrationStatus::NotConnected,
                organisation_id: None,
                delegated: false,
                delegation_enabled,
                bills_delegated: false,
                bills_delegation_enabled,
                last_error: None,
            });
        };
        Ok(InvoiceIssuerOverview {
            provider: provider.as_str().to_string(),
            configured,
            // A status the enum does not know means the CHECK constraint and
            // the enum have drifted, which is a deployment running a schema
            // this build does not understand. Reading it as `error` is the
            // honest answer, the same call `integrations::compose` makes.
            status: IntegrationStatus::from_str(&row.status).unwrap_or(IntegrationStatus::Error),
            organisation_id: row.external_organisation_id,
            delegated: row
                .enabled_capabilities
                .iter()
                .any(|c| c == Capability::Invoicing.as_str()),
            delegation_enabled,
            bills_delegated: row
                .enabled_capabilities
                .iter()
                .any(|c| c == Capability::BillsAndExpenses.as_str()),
            bills_delegation_enabled,
            last_error: row.last_error,
        })
    }

    /// Verify the state, consume it, and answer what the exchange needs.
    ///
    /// Consumed BEFORE the exchange, so a slow or failing exchange cannot
    /// be retried with the same state. The read spans tenants because the
    /// state row is what says which tenant this is, which is the same
    /// reason the contact-sync callbacks read theirs that way.
    async fn consume_state(
        &self,
        provider: InvoiceProviderKind,
        state: &str,
    ) -> AppResult<(Uuid, String, String)> {
        let invalid = || {
            AppError::BadRequest(
                "That connection attempt is no longer valid. Start again from Settings."
                    .to_string(),
            )
        };
        let (state_id, secret) = state.split_once('.').ok_or_else(invalid)?;
        let state_id = Uuid::parse_str(state_id).map_err(|_| invalid())?;

        let row: Option<OauthStateRow> = sqlx::query_as(
            "SELECT tenant_id, state_hash, code_verifier, redirect_uri, consumed_at, expires_at \
                 FROM invoice_issuer_oauth_states WHERE id = $1 AND provider = $2",
        )
        .bind(state_id)
        .bind(provider.as_str())
        // SAFETY (PMS-285): the state row is what names the tenant, so
        // this read cannot be tenant-scoped. It returns one row by
        // primary key and everything after it is scoped to the tenant
        // that row names.
        .fetch_optional(self.db.migrator_pool())
        .await?;

        let Some(row) = row else {
            return Err(invalid());
        };
        let usable = row.consumed_at.is_none()
            && row.expires_at > Utc::now()
            && verify_password(secret, &row.state_hash)
                .await
                .unwrap_or(false);
        if !usable {
            return Err(invalid());
        }

        let consumed = sqlx::query(
            "UPDATE invoice_issuer_oauth_states SET consumed_at = NOW() \
             WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(state_id)
        // SAFETY (PMS-285): same row, named by primary key, in the window
        // between proving possession and spending it. Two callbacks racing
        // the same state leave exactly one with a row affected.
        .execute(self.db.migrator_pool())
        .await?
        .rows_affected();
        if consumed == 0 {
            return Err(invalid());
        }

        Ok((row.tenant_id, row.code_verifier, row.redirect_uri))
    }

    /// Record the connection the way the rest of the subsystem reads it.
    ///
    /// `invoicing` is enabled because connecting a provider through this
    /// flow IS the delegation: an admin who authorised Xero to issue their
    /// invoices asked for exactly that, and a connected provider delegated
    /// nothing would read on the panel as connected with nothing delegated.
    async fn record_connection(
        &self,
        tenant_id: TenantId,
        provider: InvoiceProviderKind,
        organisation_id: &str,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO integrations \
                 (tenant_id, provider, status, enabled_capabilities, external_organisation_id, \
                  connected_at) \
             VALUES ($1, $2, 'connected', ARRAY['invoicing']::text[], $3, NOW()) \
             ON CONFLICT (tenant_id, provider) DO UPDATE \
               SET status = 'connected', \
                   enabled_capabilities = EXCLUDED.enabled_capabilities, \
                   external_organisation_id = EXCLUDED.external_organisation_id, \
                   connected_at = NOW(), \
                   last_error = NULL, \
                   updated_at = NOW()",
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(organisation_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// What a per-provider settings page renders (MAPPS-1143).
#[derive(Debug, Clone, serde::Serialize)]
pub struct InvoiceIssuerOverview {
    pub provider: String,
    /// Whether this DEPLOYMENT holds an application for the provider.
    /// PMS-1430: the whole answer a tenant gets, because the application is
    /// the host's and there is nothing for a tenant to edit.
    pub configured: bool,
    pub status: IntegrationStatus,
    /// The Xero organisation or QuickBooks company on the other end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organisation_id: Option<String>,
    /// Whether `invoicing` is enabled, which is what makes an invoice go
    /// through the provider rather than through Mokosh.
    pub delegated: bool,
    /// Whether delegated issuing is switched on for this DEPLOYMENT
    /// (MAPPS-1154).
    ///
    /// The fourth gate, and the one that is off everywhere by default. A
    /// tenant can be configured, connected and delegated and still have
    /// every invoice issued locally, because `IssuerDispatcher::plan`
    /// answers `Local` while this is false. The card has to say so, or it
    /// claims an arrangement the deployment has switched off.
    pub delegation_enabled: bool,
    /// Whether this tenant delegated BILLS to the provider (MAPPS-1155),
    /// which is a second decision in the other direction and not implied
    /// by having delegated invoicing.
    pub bills_delegated: bool,
    /// Whether delegated BILLS are switched on for this DEPLOYMENT
    /// (MAPPS-1155). Its own switch, so a card that reports the invoice
    /// one would be answering a different question.
    pub bills_delegation_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The integrations row, as the overview reads it.
#[derive(sqlx::FromRow)]
struct OverviewRow {
    status: String,
    enabled_capabilities: Vec<String>,
    external_organisation_id: Option<String>,
    last_error: Option<String>,
}

/// The state row, as the callback reads it back.
///
/// A named type rather than a six-wide tuple, which is past where a reader
/// can keep the order straight and what `clippy::type_complexity` says.
#[derive(sqlx::FromRow)]
struct OauthStateRow {
    tenant_id: Uuid,
    state_hash: String,
    code_verifier: String,
    redirect_uri: String,
    consumed_at: Option<chrono::DateTime<Utc>>,
    expires_at: chrono::DateTime<Utc>,
}

/// The consent URL to send an admin to.
fn authorization_url(
    provider: InvoiceProviderKind,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    pkce: &Pkce,
) -> String {
    let (endpoint, scopes) = match provider {
        InvoiceProviderKind::Xero => (xero_auth_endpoint(), XERO_SCOPES),
        InvoiceProviderKind::Quickbooks => (quickbooks_auth_endpoint(), QUICKBOOKS_SCOPES),
    };
    let query = [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", scopes),
        ("state", state),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
    .collect::<Vec<_>>()
    .join("&");
    format!("{endpoint}?{query}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The consent URL carries the host's client id, the exact redirect,
    /// the state and a PKCE challenge, and never the verifier.
    ///
    /// The last clause is the one worth a test: putting the verifier in
    /// the browser is what `plain` PKCE does and what makes an intercepted
    /// code useful again.
    #[test]
    fn the_consent_url_carries_the_challenge_and_never_the_verifier() {
        let pkce = Pkce::generate();
        let url = authorization_url(
            InvoiceProviderKind::Xero,
            "host-client",
            "https://api.example/api/v1/public/invoice-issuer/xero/callback",
            "state-id.secret",
            &pkce,
        );
        assert!(url.starts_with(&xero_auth_endpoint()), "{url}");
        assert!(url.contains("client_id=host-client"), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(
            url.contains(&urlencoding::encode(&pkce.challenge).into_owned()),
            "{url}"
        );
        assert!(
            !url.contains(&pkce.verifier),
            "the verifier stays server-side until the exchange: {url}"
        );
        assert!(
            url.contains("offline_access"),
            "without offline_access the connection lasts an hour: {url}"
        );
    }

    /// Each provider is asked for its own scopes at its own endpoint.
    #[test]
    fn each_provider_has_its_own_endpoint_and_scopes() {
        let pkce = Pkce::generate();
        let qbo = authorization_url(
            InvoiceProviderKind::Quickbooks,
            "id",
            "https://api.example/cb",
            "s",
            &pkce,
        );
        assert!(qbo.starts_with(&quickbooks_auth_endpoint()), "{qbo}");
        assert!(
            qbo.contains(&urlencoding::encode(QUICKBOOKS_SCOPES).into_owned()),
            "{qbo}"
        );
        assert!(
            !qbo.contains("accounting.transactions"),
            "Xero's scopes are not Intuit's: {qbo}"
        );
    }
}

// ---------------------------------------------------------------------------
// Routes.
// ---------------------------------------------------------------------------

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post, put};
use axum::Router;

use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::json::Json;

#[derive(Clone)]
pub struct InvoiceIssuerConnectRouterState {
    pub service: Arc<InvoiceIssuerConnectService>,
}

/// Where to send the admin's browser.
///
/// The SPA navigates to it rather than the server redirecting, the shape
/// contact sync uses (PSA-70 K): the page can warn first, and this is the
/// moment a customer's invoicing starts moving into a shared system.
#[derive(Debug, serde::Serialize)]
struct AuthorizeResponse {
    authorize_url: String,
}

#[derive(Debug, Default, serde::Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    /// Intuit names the company file here, and it is the only place it
    /// appears: unlike Xero there is no second call that would answer it.
    #[serde(rename = "realmId")]
    realm_id: Option<String>,
    error: Option<String>,
}

/// Admin-only, under `/api/v1/integrations`.
pub fn invoice_issuer_connect_routes(service: Arc<InvoiceIssuerConnectService>) -> Router {
    Router::new()
        .route("/integrations/invoice-issuer/{provider}", get(overview))
        .route(
            "/integrations/invoice-issuer/{provider}/authorize",
            post(authorize),
        )
        .route(
            "/integrations/invoice-issuer/{provider}/disconnect",
            post(disconnect),
        )
        // parity record 2026-10-25 (MAPPS-1155): no SPA caller for
        // "/integrations/invoice-issuer/{provider}/bills" until the
        // mokosh-apps half of MAPPS-1155 adds the Bills and expenses
        // toggle to the provider's page. The route lands first because
        // nothing else can set the capability, so without it the
        // dispatcher's bill half is unreachable and the server PR would
        // ship a path no deployment can exercise.
        .route(
            "/integrations/invoice-issuer/{provider}/bills",
            put(set_bills_delegation),
        )
        .with_state(InvoiceIssuerConnectRouterState { service })
}

/// The public half. Unauthenticated by construction: a browser arriving
/// from a consent screen carries no session, and the single-use state is
/// the only identity it has.
pub fn invoice_issuer_public_routes(service: Arc<InvoiceIssuerConnectService>) -> Router {
    Router::new()
        .route("/invoice-issuer/{provider}/callback", get(callback))
        .with_state(InvoiceIssuerConnectRouterState { service })
}

/// The path segment, parsed against the enum rather than passed through.
fn parse_provider(raw: &str) -> AppResult<InvoiceProviderKind> {
    InvoiceProviderKind::parse(raw).ok_or_else(|| {
        AppError::NotFound(format!(
            "{raw} is not an invoice-issuer provider. The providers are: xero, quickbooks"
        ))
    })
}

/// What the settings card reads.
async fn overview(
    State(state): State<InvoiceIssuerConnectRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path(provider): Path<String>,
) -> AppResult<Json<InvoiceIssuerOverview>> {
    let provider = parse_provider(&provider)?;
    Ok(Json(state.service.overview(user.tenant(), provider).await?))
}

async fn authorize(
    State(state): State<InvoiceIssuerConnectRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path(provider): Path<String>,
) -> AppResult<Json<AuthorizeResponse>> {
    let provider = parse_provider(&provider)?;
    let authorize_url = state
        .service
        .begin(user.tenant(), user.id, provider)
        .await?;
    Ok(Json(AuthorizeResponse { authorize_url }))
}

async fn disconnect(
    State(state): State<InvoiceIssuerConnectRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path(provider): Path<String>,
) -> AppResult<axum::http::StatusCode> {
    let provider = parse_provider(&provider)?;
    state.service.disconnect(user.tenant(), provider).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// The body of the bills toggle: one field, because one decision.
#[derive(Debug, serde::Deserialize)]
struct SetBillsDelegationRequest {
    enabled: bool,
}

async fn set_bills_delegation(
    State(state): State<InvoiceIssuerConnectRouterState>,
    _admin: RequireAdmin,
    RequireAuth(user): RequireAuth,
    Path(provider): Path<String>,
    Json(request): Json<SetBillsDelegationRequest>,
) -> AppResult<axum::http::StatusCode> {
    let provider = parse_provider(&provider)?;
    state
        .service
        .set_bills_delegation(user.tenant(), provider, request.enabled)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Always a redirect, never a JSON body: the caller is a browser.
///
/// The failure reason is a flag rather than the provider's own text,
/// because this URL ends up in a browser history and in whatever the admin
/// pastes into a support thread.
async fn callback(
    State(state): State<InvoiceIssuerConnectRouterState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    let failure = format!(
        "{}/settings/integrations?connect=failed",
        state.service.app_base.trim_end_matches('/')
    );
    let Ok(provider) = parse_provider(&provider) else {
        return Redirect::to(&failure);
    };
    if let Some(reason) = query.error.as_deref() {
        tracing::info!(
            provider = provider.as_str(),
            reason,
            "an invoice-issuer consent screen returned without a code"
        );
        return Redirect::to(&failure);
    }
    let (Some(code), Some(state_param)) = (query.code.as_deref(), query.state.as_deref()) else {
        return Redirect::to(&failure);
    };
    match state
        .service
        .complete(provider, state_param, code, query.realm_id.as_deref())
        .await
    {
        Ok(destination) => Redirect::to(&destination),
        Err(e) => {
            tracing::warn!(provider = provider.as_str(), "connect failed: {e}");
            Redirect::to(&failure)
        }
    }
}
