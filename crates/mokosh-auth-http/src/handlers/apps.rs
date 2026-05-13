//! `GET /v1/auth/apps` - list OAuth clients launchable by the signed-in
//! user. Powers the Bunyip app launcher: one tile per row returned here.
//!
//! Visibility: every non-disabled `oauth_clients` row whose `tenant_id`
//! is NULL (platform-wide) OR matches the caller's active tenant, and
//! that has at least one redirect_uri (otherwise we cannot launch it).

use axum::extract::State;
use axum::Json;
use mokosh_auth_core::OAuthClient;
use serde::Serialize;
use std::sync::Arc;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

#[derive(Debug, Serialize)]
pub struct AppView {
    pub client_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The first registered redirect_uri. The launcher uses this as the
    /// destination after the OIDC code exchange; clients with multiple
    /// redirect_uris are expected to register the canonical "post-login
    /// landing" first.
    pub redirect_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    /// `tenant_id IS NULL` on the underlying row - i.e. a platform-wide
    /// Mokosh app vs. a connected third-party app scoped to one tenant.
    /// The SPA uses this to group tiles.
    pub is_first_party: bool,
}

impl From<OAuthClient> for AppView {
    fn from(c: OAuthClient) -> Self {
        let redirect_uri = c
            .redirect_uris
            .first()
            .map(|u| u.to_string())
            .unwrap_or_default();
        AppView {
            client_id: c.client_id.0.to_string(),
            name: c.name,
            description: c.description,
            redirect_uri,
            icon_url: c.icon_url,
            is_first_party: c.tenant_id.is_none(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AppListResponse {
    pub apps: Vec<AppView>,
}

pub async fn list_apps(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(user): BearerUser,
) -> Result<Json<AppListResponse>, HttpError> {
    let clients = st
        .provider
        .clients
        .list_for_user(user.id, user.tenant_id)
        .await
        .map_err(HttpError)?;
    Ok(Json(AppListResponse {
        apps: clients
            .into_iter()
            // list_for_user already filters out empty redirect_uris but
            // double-guard here so we never surface an unlaunchable tile.
            .filter(|c| !c.redirect_uris.is_empty())
            .map(AppView::from)
            .collect(),
    }))
}
