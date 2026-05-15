//! Calendar API routes.

use axum::{extract::Query, routing::get, Json, Router};

use super::{CalendarEvent, CalendarEventFilter};
use crate::modules::auth::RequireAuth;
use crate::utils::error::AppResult;

/// Mount calendar endpoints under `/calendar` (nested by the parent router).
pub fn calendar_routes() -> Router {
    Router::new().route("/events", get(list_events))
}

/// `GET /api/v1/calendar/events?from=<rfc3339>&to=<rfc3339>`
///
/// Tenant-scoped list of events. v0.1.0 returns an empty vec because
/// there is no persistence yet; the frontend should treat that as
/// "feature partially supported - render the calendar with no events"
/// rather than as an error.
async fn list_events(
    RequireAuth(_user): RequireAuth,
    Query(_filter): Query<CalendarEventFilter>,
) -> AppResult<Json<Vec<CalendarEvent>>> {
    Ok(Json(Vec::new()))
}
