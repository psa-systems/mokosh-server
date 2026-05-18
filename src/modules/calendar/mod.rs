//! Calendar / scheduling module.
//!
//! Original v0.1.0 surface (`GET /api/v1/calendar/events`) stays; the
//! PMS-58 story extends it with:
//! - appointments CRUD (`/appointments`)
//! - user availability windows (`/users/:id/availability`)
//! - time off (`/time-off`)
//! - on-call schedules + "who's on call now" (`/on-call-schedules`, `/on-call/now`)

pub mod models;
mod routes;
pub mod service;

pub use models::*;
pub use routes::calendar_routes;
pub use service::CalendarService;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single calendar event. Matches the field set the Dioxus calendar
/// page renders, plus enough metadata to round-trip back to the API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CalendarEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub all_day: bool,
}

/// Filter for the list endpoint. Both bounds are optional; an unbounded
/// request returns every event the tenant has access to.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CalendarEventFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}
