//! Mileage-tracking DTOs (PMS-315).
//!
//! Mirrors [`crate::time_tracking`] in shape: a mileage entry is "this person
//! drove this distance for this job" rather than "worked these hours". It
//! reuses the time-tracking `ApprovalStatus` and the `tickets::BillingStatus`
//! enums so both entry kinds share one approval / billing vocabulary.

use crate::tickets::BillingStatus;
use crate::time_tracking::ApprovalStatus;
use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct MileageEntryResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub date: NaiveDate,
    pub distance_miles: Decimal,
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub task_id: Option<Uuid>,
    pub company_id: Uuid,
    pub contract_id: Option<Uuid>,
    pub notes: Option<String>,
    pub is_billable: bool,
    pub billing_status: BillingStatus,
    /// Effective per-mile rate on the entry. `None` when neither the request
    /// nor the tenant's default rate card supplied one (entry is unpriced).
    pub rate_per_mile: Option<Decimal>,
    pub total_amount: Option<Decimal>,
    pub approval_status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Joined work-item names (mirrors `TimeEntryResponse`), so the client
    /// renders the Work Item column without per-row lookups.
    pub ticket_number: Option<String>,
    pub ticket_title: Option<String>,
    pub project_name: Option<String>,
    pub task_title: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct MileageEntryFilter {
    pub user_id: Option<Uuid>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub date_from: Option<NaiveDate>,
    pub date_to: Option<NaiveDate>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateMileageEntryRequest {
    /// Only super_admin / admin / manager can attribute mileage to a
    /// different user. The route handler enforces; service trusts the caller.
    pub user_id: Uuid,
    pub date: NaiveDate,
    /// Must be > 0 and fit `NUMERIC(8, 2)`; enforced at the request layer
    /// (clean 422), by the service (clean 400), and the `distance_miles > 0`
    /// DB CHECK.
    #[validate(custom(function = crate::validation::validate_distance_miles))]
    pub distance_miles: Decimal,
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub task_id: Option<Uuid>,
    pub company_id: Uuid,
    pub contract_id: Option<Uuid>,
    pub notes: Option<String>,
    #[serde(default = "crate::default_true")]
    pub is_billable: bool,
    /// Explicit per-mile rate. `None` inherits the tenant's default rate card
    /// `default_per_mile_rate`.
    #[validate(custom(function = crate::validation::validate_rate_per_mile))]
    pub rate_per_mile: Option<Decimal>,
}

#[derive(Debug, Clone, Default, Deserialize, Validate)]
pub struct UpdateMileageEntryRequest {
    pub date: Option<NaiveDate>,
    #[validate(custom(function = crate::validation::validate_distance_miles))]
    pub distance_miles: Option<Decimal>,
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub task_id: Option<Uuid>,
    pub notes: Option<String>,
    pub is_billable: Option<bool>,
    #[validate(custom(function = crate::validation::validate_rate_per_mile))]
    pub rate_per_mile: Option<Decimal>,
}
