//! API router configuration

use axum::{
    http::{header, HeaderValue, Method},
    middleware,
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

use crate::db::Database;
use crate::modules::auth::{auth_routes, AuthMiddleware, AuthService};
use crate::modules::contacts::{contact_routes, ContactService};
use crate::modules::tenants::{tenant_routes, TenantService};
use crate::modules::tickets::{ticket_routes, TicketService};

/// Create the main API router with all routes
pub fn create_api_router(
    db: Database,
    jwt_secret: String,
    google_oauth: Arc<google_oauth_flow::Client>,
    client_origin: String,
    super_admin_domains: Vec<String>,
    cookie_secure: bool,
) -> Router {
    let cors_allowed_origin = client_origin.clone();
    // Create services
    let auth_service = AuthService::new(db.clone(), jwt_secret.clone(), super_admin_domains);
    let tenant_service = TenantService::new(db.clone());
    let contact_service = ContactService::new(db.clone());
    let ticket_service = TicketService::new(db.clone());

    // Create auth middleware
    let auth_middleware = AuthMiddleware::new(auth_service.clone());

    // Build API v1 routes
    let api_v1 = Router::new()
        // Health check
        .route("/health", get(health_check))
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
        // Calendar (stub)
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
        // Reports (stub)
        .nest("/reports", stub_routes())
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

    // Audit F13: previously CORS was Any/Any/Any (dev-friendly but unsafe
    // for any deployment that's reachable from the public internet).
    // Tighten to: only the configured CLIENT_ORIGIN, only the methods
    // we actually serve, only the headers the client sends. SPA and API
    // typically share an origin (via Dioxus proxy / outer reverse proxy)
    // so CORS rarely fires in normal use - this is defense in depth.
    let cors = CorsLayer::new()
        .allow_origin(
            cors_allowed_origin
                .parse::<HeaderValue>()
                .expect("CLIENT_ORIGIN must be a valid HTTP header value"),
        )
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
        ])
        .allow_credentials(true);

    // Combine everything
    Router::new()
        .nest("/api/v1", api_v1)
        .nest("/api/v1/portal", portal_api)
        // Apply global middleware
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
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
