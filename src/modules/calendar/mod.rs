//! Calendar / appointments module.
//!
//! v0.1.0 scope: a tenant-scoped `GET /api/v1/calendar/events` endpoint that
//! returns `Vec<CalendarEvent>` filtered by `from` / `to` query params. No
//! persistence yet - the handler returns an empty vec so the frontend can
//! wire up real fetch logic with a graceful fall-back to its demo data. A
//! follow-up adds a `calendar_events` table, repository, and create/update/delete
//! routes; the frontend's disabled "New Appointment" CTA enables itself once
//! the create endpoint exists.

mod routes;

pub use routes::calendar_routes;

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
