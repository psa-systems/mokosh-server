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
//! Appointment reminders worker (PMS-58 follow-up). The two blockers
//! the original deferral noted are both resolved here:
//! 1. [`CalendarService::with_dispatcher`] threads an optional
//!    `NotificationsService` (same pattern as `AuthService`), wired in
//!    `create_api_router`.
//! 2. The `appointment_reminders` ledger (migration 028) stamps each
//!    (appointment_id, occurrence_start, reminder_minutes) tuple so a
//!    virtual recurring occurrence is reminded exactly once per offset.
//!
//! [`CalendarReminderWorker`] runs on the shared scheduler and fires
//! `NotificationsService::dispatch(tenant_id, "appointment.reminder",
//! &ctx)` with `recipient_user_id = assigned_to_id`.

pub mod models;
mod routes;
pub mod service;
pub mod worker;

pub use models::*;
pub use routes::{calendar_routes, dispatch_routes};
pub use service::{CalendarService, ReminderCandidate};
pub use worker::CalendarReminderWorker;

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
