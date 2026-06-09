//! First-visit demo-seeding middleware (PMS-157).
//!
//! Runs *inner* of the auth middleware so [`AuthState`] is already populated.
//! For an authenticated request whose tenant this process has not yet
//! settled, it spawns the seed detached and immediately calls the next
//! handler, so seeding never adds latency to the triggering request. The
//! cheap in-process `seen` check gates the spawn, so the steady state spawns
//! nothing.

use std::sync::Arc;

use axum::{extract::Request, extract::State, middleware::Next, response::Response};

use crate::modules::auth::AuthState;

use super::SeedService;

/// State carried by [`seed_middleware`].
#[derive(Clone)]
pub struct SeedMiddlewareState {
    pub service: Arc<SeedService>,
}

pub async fn seed_middleware(
    State(state): State<SeedMiddlewareState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(auth) = request.extensions().get::<AuthState>() {
        if let (Some(tenant_id), Some(user)) = (auth.tenant_id, auth.user.as_ref()) {
            // Only spawn when this tenant has not been settled yet; after the
            // first visit the seen-set short-circuits here with no task and
            // no DB work.
            if !state.service.is_seen(tenant_id) {
                let user_id = user.id;
                let service = state.service.clone();
                tokio::spawn(async move {
                    service.ensure_demo_seeded(tenant_id, user_id).await;
                });
            }
        }
    }
    next.run(request).await
}
