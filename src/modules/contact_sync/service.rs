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

use super::google::GoogleContactsProvider;
use super::oauth::{self, OauthClient, Pkce, TokenError};
use super::provider::{ContactSyncProvider, SourceGroup};
use super::runs::{RunStatus, RUN_COLUMNS};
use super::sync::{external_id_digest, fields, ContactSyncEngine, ImportPreview, SyncReport};
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
    deleted_in_source: i64,
    selected_groups: serde_json::Value,
    sync_interval_minutes: i32,
    consecutive_failures: i32,
    open_reviews: i64,
}

impl From<ConnectionRow> for ConnectionStatus {
    fn from(row: ConnectionRow) -> Self {
        Self {
            selected_groups: serde_json::from_value(row.selected_groups).unwrap_or_default(),
            sync_interval_minutes: row.sync_interval_minutes,
            consecutive_failures: row.consecutive_failures,
            open_reviews: row.open_reviews,
            latest_run: None,
            id: row.id,
            provider: row.provider,
            account_email: row.account_email,
            is_active: row.is_active,
            sync_status: row.sync_status,
            last_sync_at: row.last_sync_at,
            last_error: row.last_error,
            connected_at: row.created_at,
            deleted_in_source: row.deleted_in_source,
        }
    }
}

/// What a completed consent did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    Connected(Uuid),
    /// The same account again, so the existing connection kept its id and
    /// got the new grant.
    Reconnected(Uuid),
}

/// The Settings card's whole read (PMS-1241).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContactSyncOverview {
    /// `integrations/google_contacts_enabled`. Off hides the connect action
    /// for everyone and stops every sync; the connection and every imported
    /// contact are kept.
    pub enabled: bool,
    /// This deployment has a Google OAuth client. Without one nobody can
    /// connect, and the card says so rather than offering a broken button.
    pub configured: bool,
    /// `null` when never connected, or disconnected.
    pub connection: Option<ConnectionStatus>,
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
    /// Linked contacts the source has deleted (PSA-70 I). They are kept and
    /// only flagged, so this is what tells an admin there is something to look
    /// at rather than something that quietly happened.
    pub deleted_in_source: i64,
    /// The label ids an admin opted into. Empty means nothing is imported.
    pub selected_groups: Vec<String>,
    pub sync_interval_minutes: i32,
    /// Failed runs in a row. What makes a broken connection visible without
    /// reading logs; `contact_sync.failing` is sent at three (PMS-1215).
    pub consecutive_failures: i32,
    /// Incoming records waiting on a reviewer.
    pub open_reviews: i64,
    /// The most recent run, active or not.
    pub latest_run: Option<RunStatus>,
}

/// One label, as the import picker offers it (PSA-70 E).
#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupOption {
    pub id: String,
    pub name: String,
    /// Google's own count, which is what the preview shows before anything
    /// is written. A contact in two selected labels is counted in both.
    pub member_count: Option<u32>,
    pub selected: bool,
}

/// One incoming record waiting on a reviewer, with every Mokosh contact it
/// might be (PSA-70 D).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReviewItem {
    pub external_id: String,
    /// The record as the sync saw it, for the side-by-side.
    pub source: serde_json::Value,
    pub queued_at: chrono::DateTime<Utc>,
    pub candidates: Vec<ReviewCandidate>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ReviewCandidate {
    pub contact_id: Uuid,
    pub match_reason: String,
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub company_name: Option<String>,
    pub title: Option<String>,
    pub phones: Vec<String>,
    /// Already linked to a different record from this connection: the "two
    /// Google contacts, one Mokosh contact" case the client warns about.
    pub already_linked: bool,
}

/// A reviewer's answer.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Resolution {
    /// This record is that contact.
    Link {
        external_id: String,
        contact_id: Uuid,
    },
    /// This record is nobody Mokosh holds.
    Create { external_id: String },
    /// Do not import this record.
    Skip { external_id: String },
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Resolved {
    pub external_id: String,
    pub contact_id: Option<Uuid>,
}

/// Where a contact came from and what is protected on it (PMS-1214).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContactProvenance {
    pub contact_id: Uuid,
    /// Every link the contact has had, live first. A disconnected or unlinked
    /// one is kept: it is the record that this contact was imported.
    pub links: Vec<ProvenanceLink>,
    pub locks: Vec<FieldLock>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ProvenanceLink {
    pub id: Uuid,
    pub provider: String,
    pub source_account_email: String,
    pub external_id: String,
    /// `created` or `linked`; absent on a link older than migration 228.
    pub origin: Option<String>,
    pub last_synced_at: Option<chrono::DateTime<Utc>>,
    pub deleted_in_source_at: Option<chrono::DateTime<Utc>>,
    pub unlinked_at: Option<chrono::DateTime<Utc>>,
    /// `unlinked` or `disconnected`.
    pub unlink_reason: Option<String>,
    pub suggested_company_id: Option<Uuid>,
    pub suggested_company_name: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct FieldLock {
    pub field: String,
    pub locked_by_user_id: Option<Uuid>,
    pub locked_by_name: Option<String>,
    pub locked_at: chrono::DateTime<Utc>,
}

/// What a removal of imported data did.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DataRemoval {
    /// The import created the contact, so it is gone. `false` means it was
    /// already in the CRM and only its link to the source was removed.
    pub contact_deleted: bool,
    pub links_removed: u64,
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
        self.assert_enabled(tenant_id).await?;
        let client = OauthClient::from_config().ok_or_else(|| {
            AppError::Configuration(
                "Google Contacts is not configured on this deployment.".to_string(),
            )
        })?;
        let redirect_uri = self.redirect_uri()?;
        let pkce = Pkce::generate();
        let secret = generate_token(48);
        let state_hash = hash_password(&secret).await?;

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
            && verify_password(secret, &state_hash).await.unwrap_or(false);
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

        let outcome = self
            .record_connection(tenant_id, started_by, &account_email, &refresh_token)
            .await?;
        let flag = match outcome {
            ConnectOutcome::Connected(_) => "connected",
            ConnectOutcome::Reconnected(_) => "reconnected",
        };
        Ok(format!(
            "{}/settings/integrations/google-contacts?contact_sync={flag}",
            self.spa_base_url.trim_end_matches('/')
        ))
    }

    /// The half of a connect that follows Google's answer: store the grant
    /// and the connection row (PMS-1212), or, when the tenant already has a
    /// live connection to the SAME account, replace its grant (PMS-1241).
    ///
    /// Reconnecting is the only way out of `reconnect_required` (PSA-70 J), and
    /// it must keep the connection: its links, runs, selection and review
    /// queue all hang off the connection id, and a disconnect-then-connect
    /// would turn every imported contact into a local record first. A
    /// DIFFERENT account is refused instead: every link names the account it
    /// came from, so swapping the account under a live connection would
    /// attribute one address book's contacts to another.
    ///
    /// Public so the suite can drive it without Google's token endpoint; the
    /// only production caller is [`Self::complete_connect`], after the state
    /// was verified and consumed.
    pub async fn record_connection(
        &self,
        tenant_id: TenantId,
        started_by: Uuid,
        account_email: &str,
        refresh_token: &str,
    ) -> AppResult<ConnectOutcome> {
        let tenant_uuid = tenant_id.get();
        let ctx = AuditCtx::system(tenant_uuid);
        if let Some(existing) = self.connection(tenant_id).await? {
            if !existing.account_email.eq_ignore_ascii_case(account_email) {
                return Err(AppError::Conflict(format!(
                    "This organization is connected to {}. Disconnect it before connecting a different Google account.",
                    existing.account_email
                )));
            }
            self.secrets
                .put(
                    &SecretKey::contact_sync(tenant_uuid, &existing.provider, existing.id),
                    refresh_token,
                )
                .await?;
            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
            sqlx::query(
                "UPDATE contact_sync_connections SET \
                     sync_status = CASE WHEN last_sync_at IS NULL THEN 'never' ELSE 'success' END, \
                     last_error = NULL, consecutive_failures = 0, failure_notified_at = NULL, \
                     is_active = TRUE, updated_at = NOW() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant_id)
            .bind(existing.id)
            .execute(&mut *tx)
            .await?;
            audit_write(
                &mut *tx,
                tenant_id,
                &ctx,
                AuditAction::Update,
                "contact_sync_connections",
                Some(existing.id),
                Some(serde_json::json!({ "sync_status": existing.sync_status })),
                Some(serde_json::json!({
                    "event": "contact_sync.reconnected",
                    "provider": existing.provider,
                    "account_email": existing.account_email,
                    "reconnected_by_user_id": started_by,
                })),
            )
            .await?;
            tx.commit().await?;
            return Ok(ConnectOutcome::Reconnected(existing.id));
        }

        // The id is minted here so the secret can be stored BEFORE the row
        // exists (PMS-968's ordering): an orphaned secret is harmless, while a
        // row claiming a credential the store never received is an integration
        // that cannot sync and cannot say why.
        let connection_id = Uuid::new_v4();
        self.secrets
            .put(
                &SecretKey::contact_sync(tenant_uuid, GOOGLE, connection_id),
                refresh_token,
            )
            .await?;

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
        .bind(account_email)
        .execute(&mut *tx)
        .await
        .map_err(
            |e| match e.as_database_error().and_then(|d| d.code()).as_deref() {
                // The live-connection index (migration 220) is the org-level
                // rule; reaching it here means a connect raced this one.
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
        Ok(ConnectOutcome::Connected(connection_id))
    }

    /// Where to send a browser whose callback failed. The reason is a shape,
    /// never the provider's text: this lands in a URL bar and a browser
    /// history.
    pub fn failure_redirect(&self) -> String {
        format!(
            "{}/settings/integrations/google-contacts?contact_sync=failed",
            self.spa_base_url.trim_end_matches('/')
        )
    }

    /// Everything the Settings card needs before it can decide what to draw
    /// (PMS-1241): whether the tenant allows the integration, whether this
    /// deployment can connect at all, and the connection if there is one.
    pub async fn overview(&self, tenant_id: TenantId) -> AppResult<ContactSyncOverview> {
        Ok(ContactSyncOverview {
            enabled: crate::modules::settings::read_google_contacts_enabled(&self.db, tenant_id)
                .await?,
            configured: OauthClient::from_config().is_some(),
            connection: self.connection(tenant_id).await?,
        })
    }

    /// Refuse while `integrations/google_contacts_enabled` is off (PSA-70 K).
    /// A 409 naming the setting, because the request is fine and the tenant's
    /// state is what stands in the way.
    pub async fn assert_enabled(&self, tenant_id: TenantId) -> AppResult<()> {
        if crate::modules::settings::read_google_contacts_enabled(&self.db, tenant_id).await? {
            Ok(())
        } else {
            Err(AppError::Conflict(
                "Google Contacts is turned off for this organization. An administrator can turn it back on in Settings, Integrations."
                    .to_string(),
            ))
        }
    }

    /// The tenant's live connection, if any.
    pub async fn connection(&self, tenant_id: TenantId) -> AppResult<Option<ConnectionStatus>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<ConnectionRow> = sqlx::query_as(
            "SELECT c.id, c.provider, c.account_email, c.is_active, c.sync_status, c.last_sync_at, \
                    c.last_error, c.created_at, c.selected_groups, c.sync_interval_minutes, \
                    c.consecutive_failures, \
                    (SELECT count(*) FROM contact_sync_links l \
                     WHERE l.connection_id = c.id AND l.unlinked_at IS NULL \
                       AND l.deleted_in_source_at IS NOT NULL) AS deleted_in_source, \
                    (SELECT count(DISTINCT k.external_id) FROM contact_sync_candidates k \
                     WHERE k.connection_id = c.id AND k.status = 'open') AS open_reviews \
             FROM contact_sync_connections c \
             WHERE c.tenant_id = $1 AND c.disconnected_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let connection_id = row.id;
        let mut status = ConnectionStatus::from(row);
        status.latest_run = sqlx::query_as(&format!(
            "SELECT {RUN_COLUMNS} FROM contact_sync_runs \
             WHERE tenant_id = $1 AND connection_id = $2 ORDER BY created_at DESC LIMIT 1"
        ))
        .bind(tenant_id)
        .bind(connection_id)
        .fetch_optional(&mut *tx)
        .await?;
        Ok(Some(status))
    }

    /// Disconnect, keeping every imported contact.
    ///
    /// The connection row is marked rather than deleted, and the refresh token
    /// is dropped from the secret store: a disconnected connection must not
    /// hold a usable credential. Every live link is closed as `disconnected`
    /// in the same transaction (PMS-1214, PSA-70 J), which is what makes the
    /// contacts local records: nothing syncs into them again, nothing about
    /// them is deleted, and the link row still names the provider and account
    /// they came from.
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
        // An import in flight stops: a queued run is cancelled outright, and a
        // running one at its next checkpoint (PMS-1215).
        sqlx::query(
            "UPDATE contact_sync_runs SET \
                 status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END, \
                 finished_at = CASE WHEN status = 'queued' THEN NOW() ELSE finished_at END, \
                 cancel_requested_at = NOW() \
             WHERE tenant_id = $1 AND connection_id = $2 AND status IN ('queued', 'running')",
        )
        .bind(tenant_id)
        .bind(connection.id)
        .execute(&mut *tx)
        .await?;
        let kept_as_local = sqlx::query(
            "UPDATE contact_sync_links \
             SET unlinked_at = NOW(), unlink_reason = 'disconnected', unlinked_by_user_id = $3, \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND connection_id = $2 AND unlinked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(connection.id)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
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
                "contacts_kept_as_local": kept_as_local,
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

    /// The live connection's id and provider, or the NotFound every caller
    /// below would otherwise spell out.
    async fn live_connection(&self, tenant_id: TenantId) -> AppResult<ConnectionStatus> {
        self.connection(tenant_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Google Contacts connection".to_string()))
    }

    /// A provider for the live connection, holding a freshly refreshed token.
    /// Refused while the integration is turned off: a read of the tenant's
    /// Google account is exactly what the switch exists to stop.
    async fn source(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<(ConnectionStatus, GoogleContactsProvider)> {
        self.assert_enabled(tenant_id).await?;
        let connection = self.live_connection(tenant_id).await?;
        let token = self
            .access_token(tenant_id, connection.id, &connection.provider)
            .await?;
        Ok((
            connection,
            GoogleContactsProvider::new(self.http.clone(), token),
        ))
    }

    /// The labels an admin can choose from, with their counts (PSA-70 E).
    pub async fn source_groups(&self, tenant_id: TenantId) -> AppResult<Vec<SourceGroup>> {
        let (_, source) = self.source(tenant_id).await?;
        Ok(source.list_groups().await?)
    }

    /// Run one sync of the tenant's live connection now (PMS-1213). The
    /// scheduled worker and the run rows that make it resumable are PMS-1215.
    pub async fn sync_now(&self, tenant_id: TenantId) -> AppResult<SyncReport> {
        let (connection, source) = self.source(tenant_id).await?;
        ContactSyncEngine::new(self.db.clone())
            .run(tenant_id, connection.id, &source)
            .await
    }

    /// The labels to choose from, marked with the current selection.
    pub async fn groups(&self, tenant_id: TenantId) -> AppResult<Vec<GroupOption>> {
        let connection = self.live_connection(tenant_id).await?;
        let groups = self.source_groups(tenant_id).await?;
        Ok(groups
            .into_iter()
            .map(|g| GroupOption {
                selected: connection.selected_groups.contains(&g.id),
                id: g.id,
                name: g.name,
                member_count: g.member_count,
            })
            .collect())
    }

    /// What importing would do, without importing (PMS-1242). `group_ids`
    /// narrows the simulation to that selection so its totals are exact;
    /// `None` simulates every labelled record for per-label figures.
    pub async fn preview(
        &self,
        tenant_id: TenantId,
        group_ids: Option<&[String]>,
    ) -> AppResult<ImportPreview> {
        let (connection, source) = self.source(tenant_id).await?;
        let selection: Option<std::collections::BTreeSet<String>> =
            group_ids.map(|ids| ids.iter().map(|g| g.trim().to_string()).collect());
        ContactSyncEngine::new(self.db.clone())
            .preview(tenant_id, connection.id, &source, selection.as_ref())
            .await
    }

    /// Replace the label selection. An empty list stops imports without
    /// disconnecting. The ids are checked for shape, not against Google: an
    /// id that names no label selects nobody, which is what it means.
    pub async fn set_selection(
        &self,
        tenant_id: TenantId,
        group_ids: &[String],
        ctx: &AuditCtx,
    ) -> AppResult<ConnectionStatus> {
        const MAX_GROUPS: usize = 200;
        let mut ids: Vec<String> = group_ids.iter().map(|g| g.trim().to_string()).collect();
        ids.sort();
        ids.dedup();
        if ids.len() > MAX_GROUPS
            || ids
                .iter()
                .any(|g| !g.starts_with("contactGroups/") || g.len() > 255)
        {
            return Err(AppError::validation_field(
                "group_ids",
                "must be Google label ids such as contactGroups/myContacts, at most 200",
            ));
        }
        let connection = self.live_connection(tenant_id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE contact_sync_connections SET selected_groups = $3, updated_at = NOW() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(connection.id)
        .bind(serde_json::json!(ids))
        .execute(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contact_sync_connections",
            Some(connection.id),
            Some(serde_json::json!({ "selected_groups": connection.selected_groups })),
            Some(serde_json::json!({
                "event": "contact_sync.selection_changed",
                "selected_groups": ids,
            })),
        )
        .await?;
        tx.commit().await?;
        self.live_connection(tenant_id).await
    }

    /// Queue an import now. The first one after connecting is `initial`.
    pub async fn queue_run(&self, tenant_id: TenantId, ctx: &AuditCtx) -> AppResult<RunStatus> {
        self.assert_enabled(tenant_id).await?;
        let connection = self.live_connection(tenant_id).await?;
        if connection.selected_groups.is_empty() {
            return Err(AppError::Conflict(
                "Choose at least one Google label to import before syncing.".to_string(),
            ));
        }
        if connection.sync_status == "reconnect_required" {
            return Err(AppError::Conflict(
                "Google has revoked this connection. Connect the account again before importing."
                    .to_string(),
            ));
        }
        let trigger = if connection.last_sync_at.is_none() {
            "initial"
        } else {
            "manual"
        };
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let run: RunStatus = sqlx::query_as(&format!(
            "INSERT INTO contact_sync_runs (tenant_id, connection_id, trigger, requested_by_user_id) \
             VALUES ($1, $2, $3, $4) RETURNING {RUN_COLUMNS}"
        ))
        .bind(tenant_id)
        .bind(connection.id)
        .bind(trigger)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match e.as_database_error().and_then(|d| d.code()).as_deref() {
            Some("23505") => AppError::Conflict(
                "An import is already queued or running for this connection.".to_string(),
            ),
            _ => e.into(),
        })?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            "contact_sync_runs",
            Some(run.id),
            None,
            Some(serde_json::json!({
                "event": "contact_sync.run_queued",
                "trigger": trigger,
            })),
        )
        .await?;
        tx.commit().await?;
        Ok(run)
    }

    /// Recent runs, newest first.
    pub async fn runs(&self, tenant_id: TenantId, limit: i64) -> AppResult<Vec<RunStatus>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Ok(sqlx::query_as(&format!(
            "SELECT {RUN_COLUMNS} FROM contact_sync_runs \
             WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2"
        ))
        .bind(tenant_id)
        .bind(limit.clamp(1, 100))
        .fetch_all(&mut *tx)
        .await?)
    }

    pub async fn run(&self, tenant_id: TenantId, run_id: Uuid) -> AppResult<RunStatus> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query_as(&format!(
            "SELECT {RUN_COLUMNS} FROM contact_sync_runs WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(run_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Import run".to_string()))
    }

    /// Stop an import. A queued run is cancelled at once; a running one stops
    /// at its next checkpoint with what landed kept and the cursor unmoved.
    pub async fn cancel_run(
        &self,
        tenant_id: TenantId,
        run_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<RunStatus> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let status: Option<String> = sqlx::query_scalar(
            "UPDATE contact_sync_runs SET \
                 status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END, \
                 finished_at = CASE WHEN status = 'queued' THEN NOW() ELSE finished_at END, \
                 cancel_requested_at = COALESCE(cancel_requested_at, NOW()) \
             WHERE tenant_id = $1 AND id = $2 AND status IN ('queued', 'running') \
             RETURNING status",
        )
        .bind(tenant_id)
        .bind(run_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(status) = status else {
            // Unknown, or already finished: say which.
            drop(tx);
            let run = self.run(tenant_id, run_id).await?;
            return Err(AppError::Conflict(format!(
                "This import has already finished ({}).",
                run.status
            )));
        };
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contact_sync_runs",
            Some(run_id),
            None,
            Some(serde_json::json!({
                "event": "contact_sync.run_cancelled",
                "status": status,
            })),
        )
        .await?;
        tx.commit().await?;
        self.run(tenant_id, run_id).await
    }

    /// Everything waiting on a reviewer, oldest first.
    pub async fn review_queue(&self, tenant_id: TenantId) -> AppResult<Vec<ReviewItem>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            external_id: String,
            source_snapshot: serde_json::Value,
            created_at: chrono::DateTime<Utc>,
            #[sqlx(flatten)]
            candidate: ReviewCandidate,
        }
        let connection = self.live_connection(tenant_id).await?;
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT k.external_id, k.source_snapshot, k.created_at, \
                    k.candidate_contact_id AS contact_id, k.match_reason, \
                    c.first_name, c.last_name, c.email, c.title, \
                    COALESCE(co.name, c.company_name) AS company_name, \
                    ARRAY(SELECT p.number FROM contact_phones p WHERE p.contact_id = c.id \
                          ORDER BY p.sort_order) AS phones, \
                    EXISTS (SELECT 1 FROM contact_sync_links l \
                            WHERE l.contact_id = c.id AND l.connection_id = k.connection_id \
                              AND l.unlinked_at IS NULL AND l.external_id <> k.external_id) \
                        AS already_linked \
             FROM contact_sync_candidates k \
             JOIN contacts c ON c.id = k.candidate_contact_id \
             LEFT JOIN companies co ON co.id = c.company_id \
             WHERE k.tenant_id = $1 AND k.connection_id = $2 AND k.status = 'open' \
             ORDER BY k.created_at, k.external_id, k.candidate_contact_id",
        )
        .bind(tenant_id)
        .bind(connection.id)
        .fetch_all(&mut *tx)
        .await?;
        let mut items: Vec<ReviewItem> = Vec::new();
        for row in rows {
            match items.iter_mut().find(|i| i.external_id == row.external_id) {
                Some(item) => item.candidates.push(row.candidate),
                None => items.push(ReviewItem {
                    external_id: row.external_id,
                    source: row.source_snapshot,
                    queued_at: row.created_at,
                    candidates: vec![row.candidate],
                }),
            }
        }
        Ok(items)
    }

    /// Answer one queued record. Every open question about it closes in the
    /// same transaction, so the next sync sees a human answered and does not
    /// ask again.
    pub async fn resolve(
        &self,
        tenant_id: TenantId,
        resolution: &Resolution,
        ctx: &AuditCtx,
    ) -> AppResult<Resolved> {
        self.assert_enabled(tenant_id).await?;
        let external_id = match resolution {
            Resolution::Link { external_id, .. }
            | Resolution::Create { external_id }
            | Resolution::Skip { external_id } => external_id.clone(),
        };
        let connection = self.live_connection(tenant_id).await?;
        let engine = ContactSyncEngine::new(self.db.clone());
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let open: Vec<(Uuid, Option<String>, serde_json::Value)> = sqlx::query_as(
            "SELECT candidate_contact_id, etag, source_snapshot FROM contact_sync_candidates \
             WHERE tenant_id = $1 AND connection_id = $2 AND external_id = $3 AND status = 'open' \
             FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(connection.id)
        .bind(&external_id)
        .fetch_all(&mut *tx)
        .await?;
        let Some((_, etag, snapshot)) = open.first().cloned() else {
            return Err(AppError::NotFound("Review item".to_string()));
        };

        let (chosen, contact_id) = match resolution {
            Resolution::Link { contact_id, .. } => {
                if !open.iter().any(|(c, _, _)| c == contact_id) {
                    return Err(AppError::validation_field(
                        "contact_id",
                        "must be one of the contacts this record was matched to",
                    ));
                }
                engine
                    .link_reviewed(
                        &mut tx,
                        tenant_id,
                        connection.id,
                        &external_id,
                        etag.as_deref(),
                        &snapshot,
                        *contact_id,
                        ctx,
                    )
                    .await
                    .map_err(already_linked)?;
                ("linked", Some(*contact_id))
            }
            Resolution::Create { .. } => {
                let created = engine
                    .create_reviewed(
                        &mut tx,
                        tenant_id,
                        connection.id,
                        &external_id,
                        etag.as_deref(),
                        &snapshot,
                        ctx,
                    )
                    .await
                    .map_err(already_linked)?;
                ("created", Some(created))
            }
            Resolution::Skip { .. } => ("skipped", None),
        };

        // The chosen pair records the decision; the pairs not chosen were
        // answered by it too, and read as skipped.
        sqlx::query(
            "UPDATE contact_sync_candidates SET \
                 status = CASE WHEN $4 = 'linked' AND candidate_contact_id = $5 THEN 'linked' \
                               WHEN $4 = 'created' THEN 'created' ELSE 'skipped' END, \
                 resolved_by_user_id = $6, resolved_at = NOW() \
             WHERE tenant_id = $1 AND connection_id = $2 AND external_id = $3 AND status = 'open'",
        )
        .bind(tenant_id)
        .bind(connection.id)
        .bind(&external_id)
        .bind(chosen)
        .bind(contact_id)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await?;
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            "contact_sync_candidates",
            contact_id,
            None,
            Some(serde_json::json!({
                "event": "contact_sync.review_resolved",
                "external_id": external_id,
                "decision": chosen,
                "contact_id": contact_id,
            })),
        )
        .await?;
        tx.commit().await?;
        Ok(Resolved {
            external_id,
            contact_id,
        })
    }

    /// Refuse a contact id that is not this tenant's, so every per-contact
    /// method below 404s the same way the contact routes do.
    async fn assert_contact(
        conn: &mut sqlx::PgConnection,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<()> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM contacts WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_one(&mut *conn)
        .await?;
        if exists {
            Ok(())
        } else {
            Err(AppError::NotFound("Contact".to_string()))
        }
    }

    /// Where a contact came from, whether the source still has it, and which
    /// of its fields a person has locked (PMS-1214).
    pub async fn provenance(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<ContactProvenance> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::assert_contact(&mut tx, tenant_id, contact_id).await?;
        let links: Vec<ProvenanceLink> = sqlx::query_as(
            "SELECT l.id, l.provider, l.source_account_email, l.external_id, l.origin, \
                    l.last_synced_at, l.deleted_in_source_at, l.unlinked_at, l.unlink_reason, \
                    l.suggested_company_id, co.name AS suggested_company_name, l.created_at \
             FROM contact_sync_links l \
             LEFT JOIN companies co ON co.id = l.suggested_company_id AND co.tenant_id = l.tenant_id \
             WHERE l.tenant_id = $1 AND l.contact_id = $2 \
             ORDER BY (l.unlinked_at IS NULL) DESC, l.created_at DESC",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut *tx)
        .await?;
        let locks: Vec<FieldLock> = sqlx::query_as(
            "SELECT k.field, k.locked_by_user_id, \
                    NULLIF(TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')), '') \
                        AS locked_by_name, \
                    k.locked_at \
             FROM contact_field_locks k \
             LEFT JOIN users u ON u.id = k.locked_by_user_id \
             WHERE k.tenant_id = $1 AND k.contact_id = $2 \
             ORDER BY k.field",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut *tx)
        .await?;
        Ok(ContactProvenance {
            contact_id,
            links,
            locks,
        })
    }

    /// Let the source write a locked field again.
    pub async fn release_lock(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        field: &str,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        if !fields::ALL.contains(&field) {
            return Err(AppError::validation_field(
                "field",
                format!("must be one of {}", fields::ALL.join(", ")),
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::assert_contact(&mut tx, tenant_id, contact_id).await?;
        let released = sqlx::query(
            "DELETE FROM contact_field_locks WHERE tenant_id = $1 AND contact_id = $2 AND field = $3",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(field)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if released == 0 {
            return Err(AppError::NotFound("Field lock".to_string()));
        }
        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "contact_field_locks",
            Some(contact_id),
            Some(serde_json::json!({ "field": field })),
            Some(serde_json::json!({
                "event": "contact_sync.lock_released",
                "contact_id": contact_id,
                "field": field,
            })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Stop syncing one contact, leaving it exactly as it is (PSA-70 J).
    ///
    /// The link row stays, marked `unlinked`, and the sync skips that source
    /// record from then on instead of linking it straight back by its email.
    pub async fn unlink(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        ctx: &AuditCtx,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::assert_contact(&mut tx, tenant_id, contact_id).await?;
        let unlinked: Vec<(Uuid, String, String)> = sqlx::query_as(
            "UPDATE contact_sync_links \
             SET unlinked_at = NOW(), unlink_reason = 'unlinked', unlinked_by_user_id = $3, \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND contact_id = $2 AND unlinked_at IS NULL \
             RETURNING id, provider, external_id",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(ctx.user_id)
        .fetch_all(&mut *tx)
        .await?;
        if unlinked.is_empty() {
            return Err(AppError::NotFound("Contact sync link".to_string()));
        }
        for (link_id, provider, external_id) in &unlinked {
            audit_write(
                &mut *tx,
                tenant_id,
                ctx,
                AuditAction::Update,
                "contact_sync_links",
                Some(*link_id),
                None,
                Some(serde_json::json!({
                    "event": "contact_sync.unlinked",
                    "contact_id": contact_id,
                    "provider": provider,
                    "external_id": external_id,
                    "contact": "kept",
                })),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Remove a person's imported data on request (PSA-70 K).
    ///
    /// A contact the import CREATED is deleted; a contact that was already in
    /// the CRM and only linked keeps its record and loses its link. Either
    /// way the link rows, the review-queue snapshots of the source record and
    /// the field locks go, and a suppression marker keyed on
    /// [`external_id_digest`] keeps every later sync from importing the person
    /// back. One transaction: a contact that tickets or invoices refer to
    /// cannot be deleted, and then NOTHING is removed, rather than the link
    /// going and the contact staying behind as if it had been created by hand.
    ///
    /// The audit row records that a removal happened, who asked and why, and
    /// deliberately not the removed values. Rows the audit log already holds
    /// from earlier writes are not rewritten: the log is append-only.
    pub async fn remove_imported_data(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        reason: &str,
        ctx: &AuditCtx,
    ) -> AppResult<DataRemoval> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(AppError::validation_field(
                "reason",
                "say who asked for the removal, or why",
            ));
        }
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        Self::assert_contact(&mut tx, tenant_id, contact_id).await?;
        let links: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT provider, external_id, origin FROM contact_sync_links \
             WHERE tenant_id = $1 AND contact_id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut *tx)
        .await?;
        if links.is_empty() {
            return Err(AppError::NotFound("Imported contact data".to_string()));
        }
        // An unknown origin keeps the contact: a guess that keeps a CRM record
        // is recoverable, a guess that deletes one is not (migration 228).
        let created = links
            .iter()
            .any(|(_, _, origin)| origin.as_deref() == Some("created"));

        for (provider, external_id, _) in &links {
            sqlx::query(
                "INSERT INTO contact_sync_suppressions \
                 (tenant_id, provider, external_id_sha256, reason, created_by_user_id) \
                 VALUES ($1, $2, $3, 'data_removed', $4) \
                 ON CONFLICT (tenant_id, provider, external_id_sha256) DO NOTHING",
            )
            .bind(tenant_id)
            .bind(provider)
            .bind(external_id_digest(external_id))
            .bind(ctx.user_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "DELETE FROM contact_sync_candidates WHERE tenant_id = $1 AND external_id = $2",
            )
            .bind(tenant_id)
            .bind(external_id)
            .execute(&mut *tx)
            .await?;
        }
        let links_removed =
            sqlx::query("DELETE FROM contact_sync_links WHERE tenant_id = $1 AND contact_id = $2")
                .bind(tenant_id)
                .bind(contact_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        sqlx::query("DELETE FROM contact_field_locks WHERE tenant_id = $1 AND contact_id = $2")
            .bind(tenant_id)
            .bind(contact_id)
            .execute(&mut *tx)
            .await?;

        if created {
            sqlx::query("DELETE FROM contacts WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(contact_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| match e.as_database_error().and_then(|d| d.code()).as_deref() {
                    Some("23503") => AppError::Conflict(
                        "This contact was imported, but tickets, invoices or other records refer to it, so it cannot be deleted. Nothing was removed. Reassign or remove those records first."
                            .to_string(),
                    ),
                    _ => e.into(),
                })?;
        }

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            "contacts",
            Some(contact_id),
            None,
            Some(serde_json::json!({
                "event": "contact_sync.imported_data_removed",
                "contact_deleted": created,
                "links_removed": links_removed,
                "reason": reason,
            })),
        )
        .await?;
        tx.commit().await?;
        Ok(DataRemoval {
            contact_deleted: created,
            links_removed,
        })
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

/// The live-link index refusing a second link for one record: a sync got
/// there between the reviewer loading the queue and answering it. The unique
/// violation arrives as the generic 409, which would tell the reviewer nothing.
fn already_linked(e: AppError) -> AppError {
    match e {
        AppError::Conflict(_) => AppError::Conflict(
            "This record was linked by a sync while it was waiting for review. Reload the queue."
                .to_string(),
        ),
        other => other,
    }
}
