//! Calendar / scheduling module.
//!
//! Original v0.1.0 surface (`GET /api/v1/calendar/events`) stays; the
//! PMS-58 story extends it with:
//! - appointments CRUD (`/appointments`) with in-memory RFC 5545
//!   recurrence expansion on the bounded range query
//! - user availability windows (`/users/:id/availability`)
//! - time off (`/time-off`)
//! - on-call schedules + "who's on call now" (`/on-call-schedules`, `/on-call/now`)
//! - aggregated dispatch board (`/dispatch`) combining all of the above
//!   for a date range
//!
//! DEFERRED - appointment reminders worker. `appointments.reminder_minutes`
//! (INT[]) exists in the schema, but a reminder dispatcher needs two
//! things this module does not yet have: (1) a handle to
//! `NotificationsService` (the `CalendarService` is constructed with only
//! a `Database` and threading a notifications handle would churn the
//! constructor + its single call site), and (2) a per-occurrence
//! "reminder already sent" marker so the worker does not re-dispatch on
//! every tick (no such column / table exists - recurring occurrences are
//! virtual, so there is no row to stamp). Adding the worker without (2)
//! would spam recipients each tick. Tracked for a follow-up that adds a
//! `sent_appointment_reminders(appointment_id, occurrence_start, channel)`
//! ledger plus the notifications handle; at that point the worker fires
//! `NotificationsService::dispatch(tenant_id, "appointment.reminder", &ctx)`.

pub mod models;
mod routes;
pub mod service;

pub use models::*;
pub use routes::{calendar_routes, dispatch_routes};
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
#[derive(Clone, Debug, Default, Deserialize, validator::Validate)]
pub struct CalendarEventFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}
