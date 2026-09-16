//! PMS-1212 (PSA-70 phase 2): connecting, disconnecting, and keeping a usable
//! access token.
//!
//! The connect is two calls with a browser trip between them. `begin_connect`
//! mints the state row and answers a consent URL; `complete_connect` is the
//! redirect Google sends the browser back to, and it carries NO session, so
//! the state row is the credential (migration 221, the PMS-136 token shape).

use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;

use super::oauth::{self, OauthClient, Pkce, TokenError};
use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::secrets::{SecretKey, SecretProvider};
use crate::utils::crypto::{generate_token, hash_password, verify_password};
use crate::utils::error::{AppError, AppResult};

/// How long a consent screen may stay open before its state expires.
///
/// Ten minutes is longer than choosing a Google account takes and far shorter
/// than a tab left open overnight, which is the window a stolen state would be
/// replayed in.
const STATE_TTL_MINUTES: i64 = 10;

/// The provider this phase implements.
const GOOGLE: &str = "google";

#[derive(Clone)]
pub struct ContactSyncService {
    db: Database,
    http: reqwest::Client,
    secrets: Arc<dyn SecretProvider>,
    /// `PUBLIC_API_BASE_URL`: the origin GOOGLE reaches this deployment at,
    /// which is what the redirect URI has to be built from. Not the SPA
    /// origin: the code exchange needs the client secret and so cannot happen
    /// in a browser.
    public_api_base: Option<String>,
    /// Where the browser is sent after the callback, so the admin lands back
    /// in Settings rather than on a JSON body.
    spa_base_url: String,
}

/// The in-flight connect, as migration 221 stores it.
///
/// A named row rather than a tuple: seven columns of mostly `Uuid` and
/// `String` is exactly the shape where a reordered `SELECT` still compiles and
/// binds the wrong value to the wrong name.
#[derive(sqlx::FromRow)]
struct OauthStateRow {
    tenant_id: Uuid,
    started_by_user_id: Uuid,
    state_hash: String,
    code_verifier: String,
    redirect_uri: String,
    consumed_at: Option<chrono::DateTime<Utc>>,
    expires_at: chrono::DateTime<Utc>,
}

/// A connection row, as the Settings card needs it.
#[derive(sqlx::FromRow)]
struct ConnectionRow {
    id: Uuid,
    provider: String,
    account_email: String,
    is_active: bool,
    sync_status: String,
    last_sync_at: Option<chrono::DateTime<Utc>>,
    last_error: Option<String>,
    created_at: chrono::DateTime<Utc>,
}

impl From<ConnectionRow> for ConnectionStatus {
    fn from(row: ConnectionRow) -> Self {
        Self {
            id: row.id,
            provider: row.provider,
            account_email: row.account_email,
            is_active: row.is_active,
            sync_status: row.sync_status,
            last_sync_at: row.last_sync_at,
            last_error: row.last_error,
            connected_at: row.created_at,
        }
    }
}

/// What one connection looks like to the Settings card.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionStatus {
    pub id: Uuid,
    pub provider: String,
    pub account_email: String,
    pub is_active: bool,
    pub sync_status: String,
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

impl ContactSyncService {
    pub fn new(
        db: Database,
        secrets: Arc<dyn SecretProvider>,
        public_api_base: Option<String>,
        spa_base_url: String,
    ) -> Self {
        Self {
            db,
            http: reqwest::Client::new(),
            secrets,
            public_api_base,
            spa_base_url,
        }
    }

    /// Where Google sends the browser back to. One function, because the value
    /// has to be byte-identical in the authorization request and the token
    /// exchange, and it is also what gets registered in the Google Cloud
    /// console (PMS-794).
    pub fn redirect_uri(&self) -> AppResult<String> {
        let base = self
            .public_api_base
            .as_deref()
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .ok_or_else(|| {
                AppError::Configuration(
                    "PUBLIC_API_BASE_URL is not set, so Google has no address to return to."
                        .to_string(),
                )
            })?;
        Ok(format!(
            "{}/api/v1/public/contact-sync/google/callback",
            base.trim_end_matches('/')
        ))
    }

    /// The consent URL for an admin to visit.
    ///
    /// Refuses when the integration is unconfigured rather than producing a
    /// URL Google will reject: an operator who has not set the client sees
    /// that, not a Google error page.
    pub async fn begin_connect(&self, tenant_id: TenantId, user_id: Uuid) -> AppResult<String> {
        let client = OauthClient::from_config().ok_or_else(|| {
            AppError::Configuration(
                "Google Contacts is not configured on this deployment.".to_string(),
            )
        })?;
        let redirect_uri = self.redirect_uri()?;
        let pkce = Pkce::generate();
        let secret = generate_token(48);
        let state_hash = hash_password(&secret)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let state_id: Uuid = sqlx::query_scalar(
            "INSERT INTO contact_sync_oauth_states \
             (tenant_id, provider, started_by_user_id, state_hash, code_verifier, redirect_uri, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(tenant_id)
        .bind(GOOGLE)
        .bind(user_id)
        .bind(&state_hash)
        .bind(&pkce.verifier)
        .bind(&redirect_uri)
        .bind(Utc::now() + Duration::minutes(STATE_TTL_MINUTES))
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        // `{id}.{secret}`, the PMS-136 shape: the id finds the row, the secret
        // proves the holder started this flow.
        let state = format!("{state_id}.{secret}");
        Ok(oauth::authorization_url(
            &client,
            &redirect_uri,
            &state,
            &pkce,
        ))
    }

    /// Finish the connect. Returns where to send the browser.
    ///
    /// SAFETY (PMS-285): this runs with no session, so the tenant comes from
    /// the state row, which the caller proved possession of. Every write below
    /// is scoped to that tenant.
    pub async fn complete_connect(&self, state: &str, code: &str) -> AppResult<String> {
        let client = OauthClient::from_config().ok_or_else(|| {
            AppError::Configuration(
                "Google Contacts is not configured on this deployment.".to_string(),
            )
        })?;
        let (state_id, secret) = state
            .split_once('.')
            .ok_or_else(|| AppError::BadRequest("That sign-in link is not valid.".to_string()))?;
        let state_id = Uuid::parse_str(state_id)
            .map_err(|_| AppError::BadRequest("That sign-in link is not valid.".to_string()))?;

        // Read on the migrator pool: there is no tenant context yet, and the
        // row is what supplies it.
        let row: Option<OauthStateRow> = sqlx::query_as(
            "SELECT tenant_id, started_by_user_id, state_hash, code_verifier, redirect_uri, \
                    consumed_at, expires_at \
             FROM contact_sync_oauth_states WHERE id = $1 AND provider = $2",
        )
        .bind(state_id)
        .bind(GOOGLE)
        .fetch_optional(self.db.migrator_pool())
        .await?;
        let Some(OauthStateRow {
            tenant_id: tenant_uuid,
            started_by_user_id: started_by,
            state_hash,
            code_verifier,
            redirect_uri,
            consumed_at,
            expires_at,
        }) = row
        else {
            return Err(AppError::BadRequest(
                "That connection attempt is no longer valid. Start again from Settings."
                    .to_string(),
            ));
        };
        // Same refusal for consumed, expired and wrong-secret: a caller
        // probing state ids learns nothing from the difference.
        let usable = consumed_at.is_none()
            && expires_at > Utc::now()
            && verify_password(secret, &state_hash).unwrap_or(false);
        if !usable {
            return Err(AppError::BadRequest(
                "That connection attempt is no longer valid. Start again from Settings."
                    .to_string(),
            ));
        }
        let tenant_id = TenantId::from_trusted(tenant_uuid);

        // Consume BEFORE the exchange, so a slow or failing exchange cannot be
        // retried with the same state.
        let consumed: u64 = sqlx::query(
            "UPDATE contact_sync_oauth_states SET consumed_at = NOW() \
             WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(state_id)
        .execute(self.db.migrator_pool())
        .await?
        .rows_affected();
        if consumed == 0 {
            return Err(AppError::BadRequest(
                "That connection attempt is no longer valid. Start again from Settings."
                    .to_string(),
            ));
        }

        let tokens = oauth::exchange_code(&self.http, &client, &redirect_uri, code, &code_verifier)
            .await
            .map_err(AppError::from)?;
        let Some(refresh_token) = tokens.refresh_token.clone() else {
            // Google withholds the refresh token when the user had already
            // consented and was not re-prompted. `prompt=consent` is sent
            // precisely to avoid this, so reaching here means the consent
            // screen was changed; say what to do rather than storing a
            // connection that dies in an hour.
            return Err(AppError::BadRequest(
                "Google did not return a refresh token. Remove this app from the Google account's third-party access and connect again."
                    .to_string(),
            ));
        };
        let account_email = oauth::account_email(&self.http, &tokens.access_token).await?;

        // The id is minted here so the secret can be stored BEFORE the row
        // exists (PMS-968's ordering): an orphaned secret is harmless, while a
        // row claiming a credential the store never received is an integration
        // that cannot sync and cannot say why.
        let connection_id = Uuid::new_v4();
        self.secrets
            .put(
                &SecretKey::contact_sync(tenant_uuid, GOOGLE, connection_id),
                &refresh_token,
            )
            .await?;

        let ctx = AuditCtx::system(tenant_uuid);
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "INSERT INTO contact_sync_connections \
             (id, tenant_id, provider, connected_by_user_id, account_email, sync_status) \
             VALUES ($1, $2, $3, $4, $5, 'never')",
        )
        .bind(connection_id)
        .bind(tenant_id)
        .bind(GOOGLE)
        .bind(started_by)
        .bind(&account_email)
        .execute(&mut *tx)
        .await
        .map_err(
            |e| match e.as_database_error().and_then(|d| d.code()).as_deref() {
                // The live-connection index (migration 220) is the org-level rule.
                Some("23505") => AppError::Conflict(
                    "This tenant already has a Google Contacts connection. Disconnect it first."
                        .to_string(),
                ),
                _ => e.into(),
            },
        )?;
        audit_write(
            &mut *tx,
            tenant_id,
            &ctx,
            AuditAction::Create,
            "contact_sync_connections",
            Some(connection_id),
            None,
            Some(serde_json::json!({
                "event": "contact_sync.connected",
                "provider": GOOGLE,
                "account_email": account_email,
                "connected_by_user_id": started_by,
            })),
        )
        .await?;
        tx.commit().await?;

        Ok(format!(
            "{}/settings?contact_sync=connected",
            self.spa_base_url.trim_end_matches('/')
        ))
    }

    /// Where to send a browser whose callback failed. The reason is a shape,
    /// never the provider's text: this lands in a URL bar and a browser
    /// history.
    pub fn failure_redirect(&self) -> String {
        format!(
            "{}/settings?contact_sync=failed",
            self.spa_base_url.trim_end_matches('/')
        )
    }

    /// The tenant's live connection, if any.
    pub async fn connection(&self, tenant_id: TenantId) -> AppResult<Option<ConnectionStatus>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<ConnectionRow> = sqlx::query_as(
            "SELECT id, provider, account_email, is_active, sync_status, last_sync_at, \
                    last_error, created_at \
             FROM contact_sync_connections \
             WHERE tenant_id = $1 AND disconnected_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(row.map(ConnectionStatus::from))
    }

    /// Disconnect, keeping every imported contact.
    ///
    /// The connection row is marked rather than deleted, and the refresh token
    /// is dropped from the secret store: a disconnected connection must not
    /// hold a usable credential. What happens to the contacts themselves -
    /// conversion to local records with their former source noted (PSA-70 J) -
    /// is PMS-1214; the links already carry provider and account for that.
    pub async fn disconnect(&self, tenant_id: TenantId, ctx: &AuditCtx) -> AppResult<()> {
        let Some(connection) = self.connection(tenant_id).await? else {
            return Err(AppError::NotFound("Google Contacts connection".to_string()));
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contact_sync_connections \
             SET disconnected_at = NOW(), is_active = FALSE, sync_token = NULL, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(connection.id)
        .execute(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "contact_sync_connections",
            Some(connection.id),
            Some(serde_json::json!({
                "provider": connection.provider,
                "account_email": connection.account_email,
            })),
            Some(serde_json::json!({
                "event": "contact_sync.disconnected",
                "imported_contacts": "kept",
            })),
        )
        .await?;
        tx.commit().await?;

        // After the row is safely marked: a delete that ran first and then hit
        // a failing commit would leave a live connection with no credential.
        if let Err(e) = self
            .secrets
            .delete(&SecretKey::contact_sync(
                tenant_id.get(),
                &connection.provider,
                connection.id,
            ))
            .await
        {
            tracing::warn!(
                connection_id = %connection.id,
                "disconnected, but the stored refresh token could not be removed: {e}"
            );
        }
        Ok(())
    }

    /// A usable access token for a connection, refreshed from the stored
    /// grant.
    ///
    /// Access tokens are never stored: they last an hour, and a stored copy is
    /// a second place a credential can leak from. A revoked grant sets
    /// `reconnect_required` here, which is the state the Settings card renders
    /// and the only one an admin can act on (PSA-70 J).
    pub async fn access_token(
        &self,
        tenant_id: TenantId,
        connection_id: Uuid,
        provider: &str,
    ) -> AppResult<String> {
        let client = OauthClient::from_config().ok_or_else(|| {
            AppError::Configuration(
                "Google Contacts is not configured on this deployment.".to_string(),
            )
        })?;
        let refresh_token = self
            .secrets
            .get(&SecretKey::contact_sync(
                tenant_id.get(),
                provider,
                connection_id,
            ))
            .await?
            .ok_or_else(|| {
                AppError::Configuration(
                    "This connection's credential is missing from the secret store.".to_string(),
                )
            })?;
        match oauth::refresh_access_token(&self.http, &client, &refresh_token).await {
            Ok(tokens) => Ok(tokens.access_token),
            Err(TokenError::GrantRevoked) => {
                self.mark_reconnect_required(tenant_id, connection_id).await;
                Err(AppError::from(TokenError::GrantRevoked))
            }
            Err(other) => Err(AppError::from(other)),
        }
    }

    /// Best effort: a failure to record the state must not mask the token
    /// failure the caller is already handling.
    async fn mark_reconnect_required(&self, tenant_id: TenantId, connection_id: Uuid) {
        let written = async {
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query(
                "UPDATE contact_sync_connections \
                 SET sync_status = 'reconnect_required', \
                     last_error = 'Google has revoked this connection.', updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(connection_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok::<(), AppError>(())
        }
        .await;
        if let Err(e) = written {
            tracing::warn!(
                connection_id = %connection_id,
                "could not record the revoked grant: {e}"
            );
        }
    }
}
