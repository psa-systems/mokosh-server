//! API router configuration

use axum::{middleware, routing::get, Router};
use std::sync::Arc;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::db::Database;
use crate::modules::auth::at_jwt::AtJwtVerifier;
use crate::modules::auth::{auth_routes, AuthMiddleware, AuthService};
use crate::modules::contacts::{contact_routes, ContactService};
use crate::modules::tenants::{tenant_routes, TenantService};
use crate::modules::tickets::{ticket_routes, TicketService};

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
    at_jwt: Option<AtJwtVerifier>,
) -> Router {
    // Create services
    let auth_service = AuthService::new(db.clone(), jwt_secret.clone());
    let tenant_service = TenantService::new(db.clone());
    let contact_service = ContactService::new(db.clone());
    let ticket_service = TicketService::new(db.clone());

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
        // Auth routes
        .nest("/auth", auth_routes(auth_service))
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

    // Combine everything
    Router::new()
        .nest("/api/v1", api_v1)
        .nest("/api/v1/portal", portal_api)
        // Apply global middleware
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Stub routes for modules not yet implemented
fn stub_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(not_implemented))
        .route("/:id", get(not_implemented))
}

async fn not_implemented() -> (axum::http::StatusCode, &'static str) {
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "Not implemented yet",
    )
}
