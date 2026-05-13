//! Postgres-backed `OAuthClientRepository`. Read-only at runtime: client
//! registration is an admin operation handled by `mokosh-bootstrap`.

use async_trait::async_trait;
use mokosh_auth_core::{AuthError, ClientId, OAuthClient, OAuthClientRepository, TenantId, UserId};

use crate::conv::{db_err, OAuthClientRow};
use crate::pool::AuthPool;

const SELECT_CLIENT: &str = r#"
    SELECT client_id, tenant_id, client_secret_hash, client_type, name,
           description, icon_url,
           redirect_uris, post_logout_redirect_uris,
           backchannel_logout_uri, lifecycle_event_uri,
           allowed_scopes, allowed_grant_types, token_endpoint_auth_method,
           require_pkce, access_token_ttl_seconds, refresh_token_ttl_seconds,
           refresh_idle_ttl_seconds, audience, disabled_at
    FROM mokosh_auth.oauth_clients
"#;

pub struct PgOAuthClientRepository {
    pool: AuthPool,
}

impl PgOAuthClientRepository {
    pub fn new(pool: AuthPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthClientRepository for PgOAuthClientRepository {
    async fn find_by_client_id(
        &self,
        client_id: ClientId,
    ) -> Result<Option<OAuthClient>, AuthError> {
        let row: Option<OAuthClientRow> =
            sqlx::query_as(&format!("{SELECT_CLIENT} WHERE client_id = $1"))
                .bind(client_id.0)
                .fetch_optional(self.pool.pg())
                .await
                .map_err(db_err)?;
        row.map(OAuthClient::try_from).transpose()
    }

    async fn list_for_user(
        &self,
        _user_id: UserId,
        tenant_id: TenantId,
    ) -> Result<Vec<OAuthClient>, AuthError> {
        let rows: Vec<OAuthClientRow> = sqlx::query_as(&format!(
            "{SELECT_CLIENT}
             WHERE disabled_at IS NULL
               AND (tenant_id IS NULL OR tenant_id = $1)
               AND array_length(redirect_uris, 1) >= 1
             ORDER BY (tenant_id IS NULL) DESC, name ASC"
        ))
        .bind(tenant_id.0)
        .fetch_all(self.pool.pg())
        .await
        .map_err(db_err)?;
        rows.into_iter().map(OAuthClient::try_from).collect()
    }
}
