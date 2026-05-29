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
use crate::modules::calendar::{calendar_routes, CalendarService};
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
    // Create services
    let auth_service = AuthService::with_mailer(
        db.clone(),
        jwt_secret.clone(),
        super_admin_emails,
        mailer.clone(),
        client_origin.clone(),
    );
    #[cfg(feature = "multi-tenant")]
    let tenant_service = TenantService::new(db.clone());
    #[cfg(not(feature = "multi-tenant"))]
    let _ = TenantService::new(db.clone());
    let contact_service = ContactService::new(db.clone());
    let ticket_service = TicketService::with_mailer(db.clone(), mailer);
    let billing_service = BillingService::with_encryption_key(db.clone(), encryption_key);
    let time_tracking_service = TimeTrackingService::new(db.clone());
    let projects_service = ProjectsService::new(db.clone());
    let calendar_service = CalendarService::new(db.clone());
    let contracts_service = ContractsService::new(db.clone());
    let assets_service = AssetsService::new(db.clone());
    let kb_service = KbService::new(db.clone());
    let notifications_service = NotificationsService::new(db.clone());
    let reports_service = ReportsService::new(db.clone());
    let rmm_service = RmmService::new(db.clone());
    let sla_service = SlaService::new(db.clone());
    let settings_service = SettingsService::new(db.clone());
    let audit_service = AuditService::new(db.clone());

    // Create auth middleware. The at+jwt verifier (when present) is
    // attached so the same middleware can authenticate either kind of
    // bearer token.
    let mut auth_middleware = AuthMiddleware::new(auth_service.clone());
    if let Some(v) = at_jwt {
        auth_middleware = auth_middleware.with_at_jwt(v);
    }

    // Build API v1 routes
    let api_v1 = Router::new()
        // Health check
        .route("/health", get(health_check))
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
        .merge(calendar_routes(calendar_service))
        .nest("/dispatch", stub_routes())
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
    let portal_api = Router::new()
        .route("/health", get(health_check))
        .merge(portal_routes(portal_service, portal_ticket_service));

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

/// Build / version info endpoint. Returns the package version, the
/// `git describe` string (matches the release tag for tagged builds), the
/// short commit hash, and the build timestamp. Useful when troubleshooting
/// to confirm exactly which revision a running server was built from.
async fn version_info() -> Json<VersionInfo> {
    Json(VersionInfo::current())
}

/// Stub routes for modules not yet implemented. Audit F12: previously
/// returned a generic "Not implemented yet"; now responds with a JSON
/// envelope that names the requested path and points at the audit
/// findings, so an early integration attempt sees something useful in
/// the response body instead of a hand-wave.
fn stub_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(not_implemented))
        .route("/{id}", get(not_implemented))
}

async fn not_implemented(
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> (
    axum::http::StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    String,
) {
    let body = format!(
        r#"{{"error":"not_implemented","path":"{}","note":"This module is on the post-OAuth backlog. See dev-docs/codebase-state.md for the audit-tracked module list."}}"#,
        uri.path()
    );
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
}
