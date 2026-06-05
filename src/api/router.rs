//! API router configuration

use axum::{
    http::{header, HeaderValue, Method, StatusCode},
    middleware,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::db::Database;
use crate::modules::assets::{assets_routes, AssetsService};
use crate::modules::audit::{audit_log_middleware, audit_routes, AuditService};
use crate::modules::auth::at_jwt::AtJwtVerifier;
use crate::modules::auth::{auth_routes, AuthMiddleware, AuthService};
use crate::modules::billing::{billing_routes, BillingService};
use crate::modules::calendar::{calendar_routes, dispatch_routes, CalendarService};
use crate::modules::contacts::{contact_routes, ContactService};
use crate::modules::contracts::{contracts_routes, ContractsService};
use crate::modules::knowledge_base::{kb_routes, KbService};
use crate::modules::notifications::{notifications_routes, NotificationsService};
use crate::modules::portal::{portal_routes, PortalAuthService};
use crate::modules::projects::{projects_routes, ProjectsService};
use crate::modules::reports::{reports_routes, ReportsService};
use crate::modules::rmm::{rmm_routes, RmmService};
use crate::modules::settings::{settings_routes, SettingsService};
use crate::modules::sla::{sla_routes, SlaService};
use crate::modules::tenants::{tenant_routes, TenantService};
use crate::modules::tickets::{ticket_routes, TicketService};
use crate::modules::time_tracking::{time_tracking_routes, TimeTrackingService};
use crate::version::VersionInfo;

/// Application state shared across all routes. Not constructed yet - the
/// router threads individual services directly; kept as the intended
/// shared-state type for handlers that adopt it later.
#[allow(dead_code)]
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub jwt_secret: String,
}

/// Create the main API router with all routes.
///
/// When `at_jwt` is `Some`, PSA endpoints accept access tokens minted by
/// `mokosh-auth` (EdDSA `at+jwt`) in addition to the legacy HS256
/// cookie. Pass `None` to run with legacy auth only (e.g. dev environments
/// where SSO env vars are not configured).
#[allow(clippy::too_many_arguments)]
pub fn create_api_router(
    db: Database,
    jwt_secret: String,
    google_oauth: Arc<google_oauth_flow::Client>,
    client_origin: String,
    cors_origins: Vec<String>,
    super_admin_emails: Vec<String>,
    cookie_secure: bool,
    at_jwt: Option<AtJwtVerifier>,
    bunyip_verifier: Option<crate::modules::auth::oidc_rs::Verifier>,
    mailer: Arc<dyn crate::utils::email::Mailer>,
    // 32-byte AES-256-GCM key. Used for at-rest encryption of any
    // per-tenant secret material (today: payment-gateway configs).
    encryption_key: [u8; 32],
) -> Router {
    let cors_origin_values: Vec<HeaderValue> = cors_origins
        .iter()
        .map(|o| {
            o.parse::<HeaderValue>().unwrap_or_else(|e| {
                panic!("CORS_ORIGIN entry {o:?} is not a valid header value: {e}")
            })
        })
        .collect();
    // Create services. NotificationsService is constructed first so a
    // shared clone can be threaded into AuthService and TicketService,
    // letting them dispatch transactional messages (password reset,
    // welcome, ticket-note email) through the notifications queue
    // instead of calling the Mailer directly. The dispatcher worker
    // spawned from main.rs drains those rows.
    let notifications_service =
        NotificationsService::with_encryption_key(db.clone(), encryption_key);
    let auth_service = AuthService::with_dispatcher(
        db.clone(),
        jwt_secret.clone(),
        super_admin_emails,
        mailer.clone(),
        client_origin.clone(),
        notifications_service.clone(),
    );
    #[cfg(feature = "multi-tenant")]
    let tenant_service = TenantService::new(db.clone());
    #[cfg(not(feature = "multi-tenant"))]
    let _ = TenantService::new(db.clone());
    let contact_service = ContactService::new(db.clone());
    let ticket_service =
        TicketService::with_dispatcher(db.clone(), mailer, notifications_service.clone());
    let billing_service = BillingService::with_encryption_key(db.clone(), encryption_key);
    let time_tracking_service = TimeTrackingService::new(db.clone());
    let projects_service = ProjectsService::new(db.clone());
    let calendar_service = CalendarService::new(db.clone());
    let contracts_service = ContractsService::new(db.clone());
    let assets_service = AssetsService::new(db.clone());
    let kb_service = KbService::new(db.clone());
    let reports_service = ReportsService::new(db.clone());
    let rmm_service =
        RmmService::with_dependencies(db.clone(), encryption_key, ticket_service.clone());
    // SLA service shares the notifications dispatcher so the
    // `sla_sweep` worker (spawned from main.rs with this same service)
    // can enqueue at-risk / breach alerts. The CRUD + evaluate routes
    // do not use the dispatcher; only the worker does.
    let sla_service = SlaService::with_dispatcher(db.clone(), notifications_service.clone());
    let settings_service = SettingsService::new(db.clone());
    let audit_service = AuditService::new(db.clone());

    // Create auth middleware. The at+jwt verifier (when present) is
    // attached so the same middleware can authenticate either kind of
    // bearer token.
    let mut auth_middleware = AuthMiddleware::new(auth_service.clone());
    if let Some(v) = at_jwt {
        auth_middleware = auth_middleware.with_at_jwt(v);
    }
    if let Some(v) = bunyip_verifier {
        auth_middleware = auth_middleware.with_bunyip(v);
    }

    // Build API v1 routes
    let api_v1 = Router::new()
        // Liveness probe: cheap, never touches downstream deps. Used by
        // orchestrators to decide whether to restart the container.
        .route("/health", get(health_check))
        // Readiness probe (PMS-130): also pings the DB, and best-effort
        // pings Infisical when `INFISICAL_BASE_URL` is set. Returns 503
        // with a JSON breakdown when a dependency is down so the
        // orchestrator drains traffic until the probe goes green.
        .route(
            "/ready",
            get({
                let db = db.clone();
                move || ready_check(db.clone())
            }),
        )
        // Build / version info (public, used for diagnostics)
        .route("/version", get(version_info))
        // Auth routes
        .nest(
            "/auth",
            auth_routes(
                auth_service,
                google_oauth,
                client_origin,
                jwt_secret.clone(),
                cookie_secure,
            ),
        )
        // Tenant management. Only mounted in multi-tenant builds: in a
        // single-tenant deployment there is exactly one tenant and the
        // CRUD endpoints would be a foot-gun. PMS-24.
        ;
    #[cfg(feature = "multi-tenant")]
    let api_v1 = api_v1.nest("/tenants", tenant_routes(tenant_service));
    let api_v1 = api_v1
        // Contact management. The canonical company endpoints live
        // under `/api/v1/contacts/companies/...` (one router for
        // companies + contacts + sites); a previous `nest("/companies",
        // Router::new())` here was dead - it matched nothing, so
        // `/api/v1/companies` returned a misleading 404 with no
        // explanation. Removed and documented (PMS-20).
        .nest("/contacts", contact_routes(contact_service.clone()))
        // Ticketing
        .nest("/tickets", ticket_routes(ticket_service))
        // Time tracking: time-entries, timesheets, timers, rounding,
        // work-types. PMS-43.
        .merge(time_tracking_routes(time_tracking_service))
        // Projects: projects + phases + task statuses + tasks +
        // dependencies. PMS-52.
        .merge(projects_routes(projects_service))
        // Calendar / scheduling: events, appointments, availability,
        // time-off, on-call. PMS-59. Mounted via merge so the routes
        // appear at their natural top-level paths.
        .merge(calendar_routes(calendar_service.clone()))
        // Dispatch view (technician scheduling board). PMS-58: the
        // calendar story owns this aggregating endpoint that combines
        // appointments (recurring series expanded), availability, time
        // off, and on-call coverage for a date range. Backed by the
        // same CalendarService as the calendar routes.
        .nest("/dispatch", dispatch_routes(calendar_service))
        // Contracts: contracts + items + hour balances + rate cards. PMS-65.
        .merge(contracts_routes(contracts_service))
        // SLA: policies, targets, business hours, holidays, evaluator. PMS-107.
        .merge(sla_routes(sla_service))
        // Billing: invoices + payments + payment-gateways + tax-rates.
        // `billing_routes` defines the full paths so the URL structure
        // stays flat. PMS-34.
        .merge(billing_routes(billing_service))
        // Assets / CMDB: types, assets, relationships, config items,
        // credential vault, audit log. PMS-72.
        .merge(assets_routes(assets_service))
        // Knowledge base: categories + articles + versions + portal feed. PMS-80.
        .merge(kb_routes(kb_service))
        // Notifications: channels + templates + prefs + inbox + rules
        // + dispatcher. PMS-86.
        .merge(notifications_routes(notifications_service))
        // RMM: connections, device mappings, alert rules, alert ingest. PMS-101.
        .merge(rmm_routes(rmm_service))
        // Reports: dashboard, tickets, time, billing, CSV export. PMS-94.
        .merge(reports_routes(reports_service))
        // Settings: tenant settings + module configs. PMS-114.
        .merge(settings_routes(settings_service))
        // Audit log read. PMS-118.
        .merge(audit_routes(audit_service.clone()))
        // Audit log middleware. PMS-119. Fires per-request after
        // auth_middleware has populated AuthState; only logs successful
        // mutating requests.
        .layer(middleware::from_fn_with_state(
            crate::modules::audit::middleware::AuditMiddlewareState {
                service: std::sync::Arc::new(audit_service),
            },
            audit_log_middleware,
        ))
        // Apply auth middleware
        .layer(middleware::from_fn_with_state(
            auth_middleware.clone(),
            crate::modules::auth::middleware::auth_middleware,
        ));

    // Build portal API routes. Portal identity is the contacts row,
    // so this surface runs its own auth middleware (mounted inside
    // `portal_routes`) and never sees `AuthMiddleware` / `AuthState`.
    let portal_service = PortalAuthService::new(db.clone(), jwt_secret.clone());
    let portal_ticket_service = TicketService::new(db.clone());
    let portal_kb_service = KbService::new(db.clone());
    let portal_api = Router::new()
        .route("/health", get(health_check))
        .merge(portal_routes(
            portal_service,
            portal_ticket_service,
            portal_kb_service,
        ));

    // CORS: SPA at msp.<tld> talks to api.msp.<tld> from a different origin,
    // so credentialed CORS must be tight (specific origins, not wildcard).
    // The list comes from the CORS_ORIGIN env var (comma-separated). The
    // bunyip apex is included so the SaaS shell can call mokosh endpoints
    // in the future without losing credentials.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(cors_origin_values))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .allow_credentials(true);

    // Combine everything. The `.fallback` swallows any non-/api/v1/* request
    // (including hitting `/` directly in a browser) with a small placeholder
    // page that links the user back to the Mokosh frontend. This keeps
    // api.msp.<tld> from leaking internal route info.
    Router::new()
        .nest("/api/v1", api_v1)
        .nest("/api/v1/portal", portal_api)
        .fallback(get(not_a_frontend))
        // Apply global middleware
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
}

/// Fallback handler for any path outside `/api/v1/*`. Renders a small
/// "this is an API endpoint" page so direct browser visits to
/// `api.msp.<tld>` are friendly instead of leaking 404 internals. The
/// link points at the Bunyip SaaS shell on the matching apex; if the
/// host can't be parsed, falls back to the staging URL.
async fn not_a_frontend(headers: axum::http::HeaderMap) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hub_link = host
        .strip_prefix("api.msp.")
        .map(|tld| format!("https://{tld}"))
        .unwrap_or_else(|| "https://a8n.systems".to_string());
    let body = format!(
        "<!doctype html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <title>Not a frontend</title>\n\
         <meta name=\"robots\" content=\"noindex\">\n\
         <style>body{{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1a1a1a}}a{{color:#0066cc}}</style>\n\
         </head>\n\
         <body>\n\
         <h1>This is an API endpoint.</h1>\n\
         <p>You're looking at the Mokosh backend API. There is no user interface here.</p>\n\
         <p>Visit <a href=\"{hub_link}\">{hub_link}</a> to reach the application.</p>\n\
         </body>\n\
         </html>\n"
    );
    (StatusCode::NOT_FOUND, Html(body))
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Readiness probe (PMS-130). Pings every external dependency the
/// running server actually talks to:
///
/// - **Database** (always): `SELECT 1` against the pool. The legacy
///   `health_check()` returns `"OK"` unconditionally; this is the
///   first probe that distinguishes a process that booted from one
///   that can actually serve a request.
/// - **Infisical** (best-effort): if the operator set
///   `INFISICAL_BASE_URL` at process start, a 1-second HTTP probe
///   against `<base>/api/status`. Mokosh-server loads Infisical
///   secrets at boot only, so a transient Infisical outage does
///   not break in-flight requests; the probe still surfaces the
///   outage because the next process restart would fail. Skipped
///   when the env var was unset at boot (single-machine deployments
///   without an Infisical sibling). The 1s timeout matches the
///   Kubernetes `timeoutSeconds` default so the orchestrator gets
///   our error body instead of timing out the whole probe.
///
/// Response shape on 200:
/// ```json
/// {"status":"ready","checks":{"db":"ok","infisical":"ok"|"skipped"}}
/// ```
///
/// On 503 the same shape is returned with the failing dependency's
/// value replaced by a short error string so the orchestrator log
/// shows the root cause without a separate metrics scrape. The
/// response sets `Cache-Control: no-store` so an intermediate
/// proxy / CDN does not pin the failing state past the next probe.
async fn ready_check(
    db: crate::db::Database,
) -> (
    StatusCode,
    [(axum::http::HeaderName, &'static str); 2],
    String,
) {
    let db_result = db.health_check().await;
    let infisical_result = probe_infisical().await;

    let db_value = match &db_result {
        Ok(()) => serde_json::Value::String("ok".into()),
        Err(e) => serde_json::Value::String(format!("error: {e}")),
    };
    let infisical_value = match &infisical_result {
        Ok(true) => serde_json::Value::String("ok".into()),
        Ok(false) => serde_json::Value::String("skipped".into()),
        Err(e) => serde_json::Value::String(format!("error: {e}")),
    };

    let any_failed = db_result.is_err() || infisical_result.is_err();
    let status_label = if any_failed { "not_ready" } else { "ready" };
    let status_code = if any_failed {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    let body = serde_json::json!({
        "status": status_label,
        "checks": {
            "db": db_value,
            "infisical": infisical_value,
        },
    });
    (
        status_code,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
}

/// Captured-at-boot Infisical probe state. The handler used to read
/// `INFISICAL_BASE_URL` and build a fresh `reqwest::Client` on every
/// request, which leaked file descriptors and re-resolved DNS under
/// repeated orchestrator polling. Cache the parsed config + the HTTP
/// client in a `OnceLock` so subsequent probes reuse the connection
/// pool. The lock is initialised on the first /ready request, not at
/// `create_api_router` time, because the env var is process-global
/// and reading it lazily keeps the router signature unchanged.
struct InfisicalProbe {
    /// `<base>/api/status` URL with trailing-slash stripped from
    /// `<base>`. Pre-built so the probe path is a const lookup.
    url: String,
    /// Sanitised display form of `<base>` (scheme + host[:port] only,
    /// no userinfo or query string) used inside error strings so the
    /// response body and access log do not echo credentials the
    /// operator may have embedded in `INFISICAL_BASE_URL`.
    display: String,
    client: reqwest::Client,
}

static INFISICAL_PROBE: std::sync::OnceLock<Option<InfisicalProbe>> = std::sync::OnceLock::new();

fn infisical_probe() -> Option<&'static InfisicalProbe> {
    INFISICAL_PROBE
        .get_or_init(|| {
            let base = std::env::var("INFISICAL_BASE_URL").ok()?;
            let trimmed = base.trim_end_matches('/').to_string();
            // Best-effort credential scrub for error strings. If
            // `INFISICAL_BASE_URL` does not parse as a URL, fall back
            // to the literal trimmed string (no leak path exists for
            // a value that does not parse anyway, but stay defensive).
            let display = match url::Url::parse(&trimmed) {
                Ok(mut u) => {
                    let _ = u.set_username("");
                    let _ = u.set_password(None);
                    u.set_query(None);
                    u.set_fragment(None);
                    u.to_string().trim_end_matches('/').to_string()
                }
                Err(_) => trimmed.clone(),
            };
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(1))
                .build()
                .ok()?;
            Some(InfisicalProbe {
                url: format!("{trimmed}/api/status"),
                display,
                client,
            })
        })
        .as_ref()
}

/// Probe Infisical's `/api/status` endpoint when the operator opted
/// in via `INFISICAL_BASE_URL`. Returns:
///
/// - `Ok(true)` - probe ran and got a 2xx response
/// - `Ok(false)` - probe skipped (env var unset)
/// - `Err(_)` - env var set, but the probe failed (DNS, TCP, non-2xx
///   response, or 1s timeout). Error messages reference only the
///   sanitised display URL so credentials in the env var stay out
///   of the response body / access log.
async fn probe_infisical() -> Result<bool, String> {
    let Some(probe) = infisical_probe() else {
        return Ok(false);
    };
    let resp = probe
        .client
        .get(&probe.url)
        .send()
        .await
        .map_err(|e| format!("{}: {e}", probe.display))?;
    if !resp.status().is_success() {
        return Err(format!("{}: status {}", probe.display, resp.status()));
    }
    Ok(true)
}

/// Build / version info endpoint. Returns the package version, the
/// `git describe` string (matches the release tag for tagged builds), the
/// short commit hash, and the build timestamp. Useful when troubleshooting
/// to confirm exactly which revision a running server was built from.
async fn version_info() -> Json<VersionInfo> {
    Json(VersionInfo::current())
}

/// Metadata describing a placeholder module surface. Used to render a
/// self-documenting 501 body (F12 / PMS-125) so an integrator hitting
/// an unimplemented endpoint learns the module name, the YouTrack
/// issue tracking the implementation, and the planned endpoint shape
/// without having to grep the source.
///
/// `dispatch` (PMS-58) was the last live caller; it now has a real
/// router. The helper is kept (not deleted) because the same
/// self-documenting-501 pattern is the agreed shape for the remaining
/// placeholder modules - the next module to graduate re-wires it the
/// same way `dispatch` did. `#[allow(dead_code)]` until then.
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct StubModule {
    /// Module slug as it appears in the URL (e.g. `dispatch`).
    name: &'static str,
    /// YouTrack key tracking the implementation (e.g. `PMS-58`).
    tracking_issue: &'static str,
    /// One-line description of the module's purpose.
    summary: &'static str,
    /// Planned endpoints as `(method, path, summary)`.
    planned_endpoints: &'static [(&'static str, &'static str, &'static str)],
}

/// Build a router that responds with a self-documenting 501 for every
/// request under the module's mount point. Replaces the previous
/// generic `Not implemented yet` body (audit F12 / PMS-125). The
/// catch-all route uses Axum's `{*rest}` wildcard so sub-paths under
/// the module also surface the same payload instead of falling
/// through to a 404.
///
/// Retained for the remaining placeholder modules; see [`StubModule`].
#[allow(dead_code)]
fn module_stub_routes(meta: StubModule) -> Router {
    Router::new()
        .route("/", get(stub_handler))
        .route("/{*rest}", get(stub_handler))
        .with_state(meta)
}

#[allow(dead_code)]
async fn stub_handler(
    axum::extract::State(meta): axum::extract::State<StubModule>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> impl IntoResponse {
    let endpoints: Vec<serde_json::Value> = meta
        .planned_endpoints
        .iter()
        .map(|(method, path, summary)| {
            serde_json::json!({
                "method": method,
                "path": path,
                "summary": summary,
            })
        })
        .collect();
    let body = serde_json::json!({
        "error": "not_implemented",
        "module": meta.name,
        "path": uri.path(),
        "summary": meta.summary,
        "tracking_issue": meta.tracking_issue,
        "tracking_url": format!(
            "https://niceguyit.myjetbrains.com/youtrack/issue/{}",
            meta.tracking_issue
        ),
        "planned_endpoints": endpoints,
        "docs": "dev-docs/codebase-state.md",
    });
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
}
