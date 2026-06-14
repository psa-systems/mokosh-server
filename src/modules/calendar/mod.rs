//! Calendar / scheduling module.
//!
//! The PMS-58 story provides:
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
