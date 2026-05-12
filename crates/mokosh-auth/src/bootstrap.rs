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
use mokosh_auth_core::TenantId;
use mokosh_auth_http::cookies::CookieConfig;
use mokosh_auth_http::{
    build_router, AuthHttpState, LettreConfig, LettreMailer, LocalAuth, LogMailer, Mailer,
    PersonalTenantCreator, RateLimiter, TenantInfoLookup, TenantNameLookup, TlsMode,
};
use mokosh_auth_oidc::{EngineConfig, OidcProvider};
use mokosh_auth_storage::{
    run_migrations, AuthPool, PgAuditLogger, PgAuthCodeRepository, PgEntitlementRepository,
    PgInviteRepository, PgMembershipRepository, PgOAuthClientRepository, PgOpSessionRepository,
    PgPasswordResetTokenRepository, PgRefreshTokenRepository, PgSignupTokenRepository,
    PgUserRepository,
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

    let cookie_cfg = CookieConfig {
        domain: cfg.cookie_domain.clone(),
        secure: !is_local_issuer(&cfg.issuer),
    };

    let invites = Arc::new(PgInviteRepository::new(auth_pool.clone()));
    let memberships = Arc::new(PgMembershipRepository::new(auth_pool.clone()));
    let signup_tokens = Arc::new(PgSignupTokenRepository::new(auth_pool.clone()));
    let password_reset_tokens = Arc::new(PgPasswordResetTokenRepository::new(auth_pool.clone()));

    let public_signup_enabled = std::env::var("MOKOSH_PUBLIC_SIGNUP_ENABLED")
        .map(|s| matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    // Personal-tenant insertion for self-signup. The auth crate does
    // not own public.tenants, so we wrap the SQL in a closure injected
    // into AuthHttpState. Tenant name = "<email>'s account"; slug must
    // be unique so we hash the email for the slug.
    let tenant_pool_create = auth_pool.clone();
    let create_personal_tenant: PersonalTenantCreator = Arc::new(move |email: String| {
        let pool = tenant_pool_create.clone();
        Box::pin(async move {
            // Slug: take a 12-char b64-of-sha256 of the email so it is
            // stable per email but does not leak the email in the URL
            // (matches the 12-char convention used elsewhere). The
            // tenant name is human-readable.
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(email.as_bytes());
            let slug = format!(
                "personal-{}",
                URL_SAFE_NO_PAD.encode(&digest[..9])
            );
            let display = format!("{}'s account", email);
            let id: uuid::Uuid = sqlx::query_scalar(
                "INSERT INTO public.tenants (name, slug, kind, status)
                 VALUES ($1, $2, 'personal', 'active')
                 RETURNING id",
            )
            .bind(&display)
            .bind(&slug)
            .fetch_one(pool.pg())
            .await
            .map_err(|e| {
                mokosh_auth_core::AuthError::Storage(format!("create personal tenant: {e}"))
            })?;
            Ok(TenantId(id))
        })
    });

    // Phase-1 mailer: log link to tracing. Production deploys swap this
    // for `LettreMailer` once SMTP is wired (see docs/mokosh-auth/04-email.md).
    let accept_base_url = std::env::var("MOKOSH_ACCEPT_BASE_URL")
        .or_else(|_| std::env::var("CLIENT_ORIGIN"))
        .unwrap_or_else(|_| cfg.issuer.as_str().trim_end_matches('/').to_string());

    // The login URL is the SPA's `/login` page, hosted on the SPA host
    // (mokosh-clients). When `/oauth2/authorize` needs to ask the user
    // to sign in, it 302s here with `?return_to=<authorize_query>` and
    // the SPA bounces back after a successful login. See
    // docs/mokosh-auth/09-single-login-bridge.md.
    //
    // Resolution order:
    //   1. MOKOSH_AUTH_LOGIN_URL (explicit override)
    //   2. <accept_base_url>/login (production default; same host the
    //      SPA is hosted on, so the cookie path covers everything)
    //   3. <issuer>/login (last-resort dev fallback; the OP login UI is
    //      no longer rendered server-side, so a deployment that hits
    //      this branch is misconfigured)
    let login_url = std::env::var("MOKOSH_AUTH_LOGIN_URL")
        .ok()
        .and_then(|s| Url::parse(&s).ok())
        .or_else(|| {
            Url::parse(&format!(
                "{}/login",
                accept_base_url.trim_end_matches('/')
            ))
            .ok()
        })
        .unwrap_or_else(|| {
            let mut u = cfg.issuer.clone();
            u.path_segments_mut()
                .expect("issuer URL is a base")
                .pop_if_empty()
                .push("login");
            u
        });
    if login_url.scheme() != "https" {
        let host = login_url.host_str().unwrap_or("");
        let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        if !is_loopback {
            tracing::warn!(
                login_url = %login_url,
                "MOKOSH_AUTH_LOGIN_URL is not HTTPS; downstream OIDC redirects will break secure-context guards"
            );
        }
    }
    // Mailer selection. SMTP_HOST set + parseable SMTP_FROM -> real
    // LettreMailer. Otherwise -> LogMailer (links go to tracing, the
    // dev fallback). Misconfiguration (host set but other required
    // fields missing or invalid) is a hard error so we don't silently
    // start a prod deploy with email going nowhere. See
    // docs/mokosh-smtp/03-config-and-bootstrap.md.
    let mailer: Arc<dyn Mailer> = match resolve_mailer_config(&accept_base_url)? {
        Some(lettre_cfg) => {
            // Log the resolved config (minus password) at INFO so an
            // operator can confirm the mailer is wired post-deploy.
            tracing::info!(
                target: "mokosh_auth.mailer",
                smtp_host = %lettre_cfg.host,
                smtp_port = %lettre_cfg.port,
                smtp_tls  = %lettre_cfg.tls.as_str(),
                smtp_user = %lettre_cfg.username.as_deref().unwrap_or("(none)"),
                from      = %lettre_cfg.from,
                "outbound email enabled (LettreMailer)"
            );
            Arc::new(
                LettreMailer::new(lettre_cfg)
                    .map_err(|e| BootstrapError::Config(e.to_string()))?,
            )
        }
        None => {
            tracing::warn!(
                target: "mokosh_auth.mailer",
                "outbound email NOT configured; using LogMailer (links go to docker logs)",
            );
            Arc::new(LogMailer {
                accept_base_url: accept_base_url.clone(),
            })
        }
    };

    // Tenant-name lookup: the auth crates do not own public.tenants, so
    // we inject a closure that runs a single query against the same
    // pool. Bounds the cross-schema coupling to one line.
    let tenant_pool = auth_pool.clone();
    let tenant_name: TenantNameLookup = Arc::new(move |tid: TenantId| {
        let pool = tenant_pool.clone();
        Box::pin(async move {
            sqlx::query_scalar::<_, String>("SELECT name FROM public.tenants WHERE id = $1")
                .bind(tid.0)
                .fetch_optional(pool.pg())
                .await
                .ok()
                .flatten()
        })
    });

    let tenant_info_pool = auth_pool.clone();
    let tenant_info: TenantInfoLookup = Arc::new(move |tid: TenantId| {
        let pool = tenant_info_pool.clone();
        Box::pin(async move {
            sqlx::query_as::<_, (String, String)>(
                "SELECT name, kind FROM public.tenants WHERE id = $1",
            )
            .bind(tid.0)
            .fetch_optional(pool.pg())
            .await
            .ok()
            .flatten()
        })
    });

    let state = Arc::new(AuthHttpState {
        provider: provider.clone(),
        local_auth,
        cookie_cfg,
        login_url,
        rate_limiter: Arc::new(RateLimiter::new()),
        invites,
        memberships,
        signup_tokens,
        password_reset_tokens,
        public_signup_enabled,
        create_personal_tenant,
        mailer,
        accept_base_url,
        tenant_name,
        tenant_info,
    });

    Ok(MokoshAuth { provider, state })
}

/// Heuristic for "are we in dev?": treats localhost / 127.0.0.1 issuers
/// as dev so cookies are not flagged Secure (which would be ignored by
/// browsers over plain HTTP anyway).
fn is_local_issuer(u: &Url) -> bool {
    matches!(u.host_str(), Some("localhost") | Some("127.0.0.1"))
}

/// Read SMTP_* env vars and return either a populated `LettreConfig`
/// or `None` (caller falls back to LogMailer). Misconfiguration (host
/// set but other required fields missing) is a hard error: we refuse
/// to boot rather than silently start a prod deploy with emails going
/// nowhere.
///
/// Contract:
///   - `SMTP_HOST` empty / unset      -> Ok(None) (LogMailer path).
///   - `SMTP_HOST` set:               -> require SMTP_PORT (u16) and
///                                       SMTP_FROM.
///   - `SMTP_USERNAME` set with empty -> treated as unset.
///   - `SMTP_USERNAME` set, _PASSWORD -> hard error (almost always a typo).
///     missing
///   - `SMTP_TLS` defaults to starttls; values: none|starttls|implicit.
fn resolve_mailer_config(accept_base_url: &str) -> Result<Option<LettreConfig>, BootstrapError> {
    let host = match std::env::var("SMTP_HOST") {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return Ok(None),
    };

    let port: u16 = std::env::var("SMTP_PORT")
        .map_err(|_| BootstrapError::Config("SMTP_PORT required when SMTP_HOST is set".into()))?
        .trim()
        .parse()
        .map_err(|e| BootstrapError::Config(format!("SMTP_PORT is not a u16: {e}")))?;

    let from = std::env::var("SMTP_FROM")
        .map_err(|_| BootstrapError::Config("SMTP_FROM required when SMTP_HOST is set".into()))?;
    if from.trim().is_empty() {
        return Err(BootstrapError::Config("SMTP_FROM is empty".into()));
    }

    let username = std::env::var("SMTP_USERNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let password = std::env::var("SMTP_PASSWORD").ok().filter(|s| !s.is_empty());
    if username.is_some() && password.is_none() {
        return Err(BootstrapError::Config(
            "SMTP_USERNAME set but SMTP_PASSWORD missing".into(),
        ));
    }

    let tls = match std::env::var("SMTP_TLS")
        .as_deref()
        .map(str::trim)
        .unwrap_or("starttls")
    {
        "none" => TlsMode::None,
        "starttls" => TlsMode::StartTls,
        "implicit" => TlsMode::ImplicitTls,
        other => {
            return Err(BootstrapError::Config(format!(
                "SMTP_TLS must be one of none|starttls|implicit, got '{other}'"
            )));
        }
    };

    Ok(Some(LettreConfig {
        host,
        port,
        username,
        password,
        from,
        tls,
        accept_base_url: accept_base_url.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env var mutation is process-global; serialize so tests do not
    // see each other's SMTP_* values.
    static ENV: Mutex<()> = Mutex::new(());

    /// Lock the env mutex, scrub every SMTP_* var, set the supplied
    /// pairs, run the resolver, then restore. Returns the resolver
    /// result. Safe to use in parallel test runs because every call
    /// goes through the mutex.
    fn with_smtp_env<F, R>(pairs: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _g = ENV.lock().unwrap_or_else(|p| p.into_inner());
        let keys = [
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_USERNAME",
            "SMTP_PASSWORD",
            "SMTP_FROM",
            "SMTP_TLS",
        ];
        // Snapshot + clear.
        let snapshot: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(*k).ok())).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        for (k, v) in pairs {
            std::env::set_var(k, v);
        }
        let out = f();
        // Restore.
        for k in keys {
            std::env::remove_var(k);
        }
        for (k, v) in snapshot {
            if let Some(v) = v {
                std::env::set_var(k, v);
            }
        }
        out
    }

    #[test]
    fn no_smtp_host_returns_none() {
        let cfg = with_smtp_env(&[], || resolve_mailer_config("https://x")).unwrap();
        assert!(cfg.is_none(), "missing SMTP_HOST must select LogMailer");
    }

    #[test]
    fn empty_smtp_host_returns_none() {
        // Whitespace-only counts as unset; the resolver trims.
        let cfg =
            with_smtp_env(&[("SMTP_HOST", "  ")], || resolve_mailer_config("https://x")).unwrap();
        assert!(cfg.is_none());
    }

    #[test]
    fn smtp_host_without_from_is_hard_error() {
        let res = with_smtp_env(
            &[("SMTP_HOST", "mailpit"), ("SMTP_PORT", "1025")],
            || resolve_mailer_config("https://x"),
        );
        assert!(matches!(res, Err(BootstrapError::Config(_))));
    }

    #[test]
    fn smtp_host_without_port_is_hard_error() {
        let res = with_smtp_env(
            &[
                ("SMTP_HOST", "mailpit"),
                ("SMTP_FROM", "Mokosh <noreply@x.test>"),
            ],
            || resolve_mailer_config("https://x"),
        );
        assert!(matches!(res, Err(BootstrapError::Config(_))));
    }

    #[test]
    fn smtp_port_must_parse_as_u16() {
        let res = with_smtp_env(
            &[
                ("SMTP_HOST", "mailpit"),
                ("SMTP_PORT", "not-a-number"),
                ("SMTP_FROM", "Mokosh <noreply@x.test>"),
            ],
            || resolve_mailer_config("https://x"),
        );
        assert!(matches!(res, Err(BootstrapError::Config(_))));
    }

    #[test]
    fn username_without_password_is_hard_error() {
        let res = with_smtp_env(
            &[
                ("SMTP_HOST", "mailpit"),
                ("SMTP_PORT", "1025"),
                ("SMTP_FROM", "Mokosh <noreply@x.test>"),
                ("SMTP_USERNAME", "alice"),
            ],
            || resolve_mailer_config("https://x"),
        );
        match res {
            Err(BootstrapError::Config(msg)) => {
                assert!(msg.contains("SMTP_PASSWORD"), "unexpected msg: {msg}")
            }
            Err(e) => panic!("expected Config error, got different error: {e}"),
            Ok(_) => panic!("expected Config error, got Ok"),
        }
    }

    #[test]
    fn unknown_smtp_tls_is_hard_error() {
        let res = with_smtp_env(
            &[
                ("SMTP_HOST", "mailpit"),
                ("SMTP_PORT", "1025"),
                ("SMTP_FROM", "Mokosh <noreply@x.test>"),
                ("SMTP_TLS", "unicorns"),
            ],
            || resolve_mailer_config("https://x"),
        );
        assert!(matches!(res, Err(BootstrapError::Config(_))));
    }

    #[test]
    fn full_smtp_env_returns_some_with_expected_values() {
        let cfg = with_smtp_env(
            &[
                ("SMTP_HOST", "mailpit"),
                ("SMTP_PORT", "1025"),
                ("SMTP_FROM", "Mokosh <noreply@x.test>"),
                ("SMTP_USERNAME", "alice"),
                ("SMTP_PASSWORD", "hunter2"),
                ("SMTP_TLS", "implicit"),
            ],
            || resolve_mailer_config("https://accept.x"),
        )
        .unwrap()
        .expect("Some(cfg)");
        assert_eq!(cfg.host, "mailpit");
        assert_eq!(cfg.port, 1025);
        assert_eq!(cfg.from, "Mokosh <noreply@x.test>");
        assert_eq!(cfg.username.as_deref(), Some("alice"));
        assert_eq!(cfg.password.as_deref(), Some("hunter2"));
        assert_eq!(cfg.tls, TlsMode::ImplicitTls);
        assert_eq!(cfg.accept_base_url, "https://accept.x");
    }

    #[test]
    fn smtp_tls_defaults_to_starttls() {
        let cfg = with_smtp_env(
            &[
                ("SMTP_HOST", "mailpit"),
                ("SMTP_PORT", "587"),
                ("SMTP_FROM", "Mokosh <noreply@x.test>"),
            ],
            || resolve_mailer_config("https://accept.x"),
        )
        .unwrap()
        .expect("Some(cfg)");
        assert_eq!(cfg.tls, TlsMode::StartTls);
    }

    #[test]
    fn empty_username_is_treated_as_unset() {
        // SMTP_USERNAME="" must NOT trip the "username without
        // password" guard. mailpit and other anonymous relays rely
        // on this.
        let cfg = with_smtp_env(
            &[
                ("SMTP_HOST", "mailpit"),
                ("SMTP_PORT", "1025"),
                ("SMTP_FROM", "Mokosh <noreply@x.test>"),
                ("SMTP_USERNAME", ""),
                ("SMTP_TLS", "none"),
            ],
            || resolve_mailer_config("https://accept.x"),
        )
        .unwrap()
        .expect("Some(cfg)");
        assert!(cfg.username.is_none());
        assert!(cfg.password.is_none());
    }
}
