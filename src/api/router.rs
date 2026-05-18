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
use crate::modules::auth::at_jwt::AtJwtVerifier;
use crate::modules::auth::{auth_routes, AuthMiddleware, AuthService};
use crate::modules::calendar::calendar_routes;
use crate::modules::reports::{reports_routes, ReportsService};
use crate::modules::contacts::{contact_routes, ContactService};
use crate::modules::tenants::{tenant_routes, TenantService};
use crate::modules::tickets::{ticket_routes, TicketService};
use crate::version::VersionInfo;

/// Application state shared across all routes
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
pub fn create_api_router(
    db: Database,
    jwt_secret: String,
    google_oauth: Arc<google_oauth_flow::Client>,
    client_origin: String,
    cors_origins: Vec<String>,
    super_admin_domains: Vec<String>,
    cookie_secure: bool,
    at_jwt: Option<AtJwtVerifier>,
) -> Router {
    let cors_origin_values: Vec<HeaderValue> = cors_origins
        .iter()
        .map(|o| {
            o.parse::<HeaderValue>()
                .unwrap_or_else(|e| panic!("CORS_ORIGIN entry {o:?} is not a valid header value: {e}"))
        })
        .collect();
    // Create services
    let auth_service = AuthService::new(db.clone(), jwt_secret.clone(), super_admin_domains);
    let tenant_service = TenantService::new(db.clone());
    let contact_service = ContactService::new(db.clone());
    let ticket_service = TicketService::new(db.clone());
    let reports_service = ReportsService::new(db.clone());

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
        // Tenant management (multi-tenant mode)
        .nest("/tenants", tenant_routes(tenant_service))
        // Contact management
        .nest("/contacts", contact_routes(contact_service.clone()))
        .nest("/companies", Router::new()) // Alias handled by contact routes
        // Ticketing
        .nest("/tickets", ticket_routes(ticket_service))
        // Time tracking (stub)
        .nest("/time-entries", stub_routes())
        .nest("/timesheets", stub_routes())
        // Projects (stub)
        .nest("/projects", stub_routes())
        .nest("/tasks", stub_routes())
        // Calendar
        .nest("/calendar", calendar_routes())
        .nest("/appointments", stub_routes())
        .nest("/dispatch", stub_routes())
        // Contracts (stub)
        .nest("/contracts", stub_routes())
        .nest("/rate-cards", stub_routes())
        // SLA (stub)
        .nest("/sla-policies", stub_routes())
        .nest("/business-hours", stub_routes())
        // Billing (stub)
        .nest("/invoices", stub_routes())
        .nest("/payments", stub_routes())
        // Assets (stub)
        .nest("/assets", stub_routes())
        .nest("/asset-types", stub_routes())
        .nest("/credentials", stub_routes())
        // Knowledge base (stub)
        .nest("/kb/articles", stub_routes())
        .nest("/kb/categories", stub_routes())
        // Notifications (stub)
        .nest("/notifications", stub_routes())
        .nest("/notification-channels", stub_routes())
        // RMM (stub)
        .nest("/rmm/connections", stub_routes())
        .nest("/rmm/devices", stub_routes())
        // Reports: dashboard, tickets, time, billing, CSV export. PMS-94.
        .merge(reports_routes(reports_service))
        // Settings (stub)
        .nest("/settings", stub_routes())
        // Apply auth middleware
        .layer(middleware::from_fn_with_state(
            auth_middleware.clone(),
            crate::modules::auth::middleware::auth_middleware,
        ));

    // Build portal API routes (separate auth context)
    let portal_api = Router::new()
        .route("/health", get(health_check))
        // Portal auth
        .nest("/auth", stub_routes())
        // Portal tickets
        .nest("/tickets", stub_routes())
        // Portal invoices
        .nest("/invoices", stub_routes())
        // Portal KB
        .nest("/kb", stub_routes());

    // CORS: SPA at msp.<tld> talks to msp-api.<tld> from a different origin,
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
    // msp-api.<tld> from leaking internal route info.
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
/// `msp-api.<tld>` are friendly instead of leaking 404 internals. The
/// link points at the Bunyip SaaS shell on the matching apex; if the
/// host can't be parsed, falls back to the staging URL.
async fn not_a_frontend(headers: axum::http::HeaderMap) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hub_link = host
        .strip_prefix("msp-api.")
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
