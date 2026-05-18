//! Time-tracking HTTP routes. Endpoints land incrementally across PMS-42.

use std::sync::Arc;

use axum::Router;

use super::service::TimeTrackingService;

#[derive(Clone)]
pub struct TimeTrackingRouterState {
    pub service: Arc<TimeTrackingService>,
}

/// Build the time-tracking router. Empty in the scaffold commit; later
/// commits add endpoints.
pub fn time_tracking_routes(service: TimeTrackingService) -> Router {
    let _state = TimeTrackingRouterState {
        service: Arc::new(service),
    };
    Router::new()
}
