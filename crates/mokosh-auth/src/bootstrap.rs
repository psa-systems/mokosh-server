//! `bootstrap`: turn an [`AuthConfig`] plus a `PgPool` into a fully wired
//! [`MokoshAuth`] handle holding the OIDC provider and the Axum router.
//!
//! Call sites (mokosh-server's `main.rs`):
//!
//! ```ignore
//! let pool = sqlx::PgPool::connect(&database_url).await?;
//! let auth = mokosh_auth::bootstrap(auth_cfg, pool).await?;
//! let app = Router::new()
//!     .merge(auth.router())            // mounts /.well-known, /oauth2, /v1/auth
//!     .nest("/v1/psa", psa_routes());
//! ```
//!
//! Migrations are applied here on startup so a fresh deploy comes up with
//! the schema in place.

use axum::Router;
use chrono::Duration;
use mokosh_auth_core::{Clock, time::SystemClock};
use mokosh_auth_crypto::OidcKeySet;
use mokosh_auth_http::cookies::CookieConfig;
use mokosh_auth_http::{build_router, AuthHttpState, LocalAuth, RateLimiter};
use mokosh_auth_oidc::{EngineConfig, OidcProvider};
use mokosh_auth_storage::{
    run_migrations, AuthPool, PgAuditLogger, PgAuthCodeRepository, PgEntitlementRepository,
    PgOAuthClientRepository, PgOpSessionRepository, PgRefreshTokenRepository, PgUserRepository,
};
use std::sync::Arc;
use url::Url;

use crate::config::AuthConfig;

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("key load: {0}")]
    Keys(#[from] mokosh_auth_crypto::KeyError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("invalid config: {0}")]
    Config(String),
}

/// The fully wired auth subsystem. Hand the `Router` to your top-level
/// Axum app; keep `provider` if you want to use the OIDC engine
/// programmatically (e.g. for admin tooling).
pub struct MokoshAuth {
    pub provider: OidcProvider,
    pub state: Arc<AuthHttpState>,
}

impl MokoshAuth {
    pub fn router(&self) -> Router {
        build_router(Arc::clone(&self.state))
    }
}

/// Wire everything. Runs migrations as a side effect.
pub async fn bootstrap(
    cfg: AuthConfig,
    pool: sqlx::PgPool,
) -> Result<MokoshAuth, BootstrapError> {
    let auth_pool = AuthPool::from_pool(pool);
    run_migrations(&auth_pool)
        .await
        .map_err(|e| BootstrapError::Storage(e.to_string()))?;

    let keys = Arc::new(OidcKeySet::load(
        &cfg.jwt_private_key_path,
        &cfg.jwt_active_kid,
        &cfg.jwt_public_keys_dir,
    )?);

    let users = Arc::new(PgUserRepository::new(auth_pool.clone()));
    let clients = Arc::new(PgOAuthClientRepository::new(auth_pool.clone()));
    let sessions = Arc::new(PgOpSessionRepository::new(auth_pool.clone()));
    let codes = Arc::new(PgAuthCodeRepository::new(auth_pool.clone()));
    let refresh = Arc::new(PgRefreshTokenRepository::new(auth_pool.clone()));
    let entitlements = Arc::new(PgEntitlementRepository::new(auth_pool.clone()));
    let audit = Arc::new(PgAuditLogger::new(auth_pool.clone()));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

    let engine_cfg = EngineConfig {
        issuer: cfg.issuer.clone(),
        authorization_code_ttl: cfg.authorization_code_ttl,
        op_session_ttl: cfg.op_session_ttl,
        default_access_token_ttl: cfg.access_token_ttl,
        default_refresh_token_ttl: cfg.refresh_token_ttl,
        default_refresh_idle_ttl: cfg.refresh_idle_ttl,
        leeway: Duration::seconds(30),
    };

    let provider = OidcProvider::new(
        engine_cfg,
        Arc::clone(&keys),
        users.clone(),
        clients,
        sessions.clone(),
        codes,
        refresh,
        entitlements,
        audit.clone(),
        clock,
    );

    let local_auth = Arc::new(LocalAuth {
        users,
        sessions,
        audit,
        op_session_ttl: cfg.op_session_ttl,
    });

    // The login URL is hosted by the front-end (mokosh-clients). It is
    // computed by appending `/login` to the configured issuer host's
    // *origin*, but in practice this is a separate host. The host
    // application can override this by mutating `state.login_url` after
    // bootstrap, or by configuring `MOKOSH_AUTH_LOGIN_URL` in a future
    // iteration. For now, default to <issuer>/login.
    let mut login_url = cfg.issuer.clone();
    login_url
        .path_segments_mut()
        .map_err(|_| BootstrapError::Config("issuer URL cannot be a base".into()))?
        .pop_if_empty()
        .push("login");

    let cookie_cfg = CookieConfig {
        domain: cfg.cookie_domain.clone(),
        secure: !is_local_issuer(&cfg.issuer),
    };

    let state = Arc::new(AuthHttpState {
        provider: provider.clone(),
        local_auth,
        cookie_cfg,
        login_url,
        rate_limiter: Arc::new(RateLimiter::new()),
    });

    Ok(MokoshAuth { provider, state })
}

/// Heuristic for "are we in dev?": treats localhost / 127.0.0.1 issuers
/// as dev so cookies are not flagged Secure (which would be ignored by
/// browsers over plain HTTP anyway).
fn is_local_issuer(u: &Url) -> bool {
    matches!(u.host_str(), Some("localhost") | Some("127.0.0.1"))
}
