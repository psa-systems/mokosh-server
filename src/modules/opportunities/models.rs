//! Wire types for the opportunities module.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// The six pipeline stages. Kept as a constant slice so the SPA can list
/// them without a second copy of the enum.
pub const STAGES: &[&str] = &[
    "lead",
    "qualified",
    "proposal",
    "negotiation",
    "won",
    "lost",
];

/// A closed opportunity carries one of these outcomes; an open one
/// carries `None`.
pub const OUTCOMES: &[&str] = &["won", "lost"];

/// True for the two stages that close an opportunity.
pub fn is_closed_stage(stage: &str) -> bool {
    stage == "won" || stage == "lost"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opportunity {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_id: Uuid,
    pub contact_id: Option<Uuid>,
    pub title: String,
    pub value_amount: Option<Decimal>,
    pub currency: String,
    pub stage: String,
    pub expected_close_date: Option<NaiveDate>,
    pub outcome: Option<String>,
    pub quote_id: Option<Uuid>,
    pub notes: Option<String>,
    pub created_by_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateOpportunityRequest {
    pub company_id: Uuid,
    #[serde(default)]
    pub contact_id: Option<Uuid>,
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    #[serde(default)]
    pub value_amount: Option<Decimal>,
    #[serde(default)]
    pub currency: Option<String>,
    /// Optional on create: an omitted stage defaults to `lead`.
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub expected_close_date: Option<NaiveDate>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateOpportunityRequest {
    #[serde(default)]
    pub contact_id: Option<Option<Uuid>>,
    #[serde(default)]
    #[validate(length(min = 1, max = 255))]
    pub title: Option<String>,
    #[serde(default)]
    pub value_amount: Option<Option<Decimal>>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub expected_close_date: Option<Option<NaiveDate>>,
    /// Link to the quote raised from this opportunity. `Some(Some(_))`
    /// sets it, `Some(None)` clears it, absent leaves it alone.
    #[serde(default)]
    pub quote_id: Option<Option<Uuid>>,
    #[serde(default)]
    pub notes: Option<Option<String>>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CloseOpportunityRequest {
    /// Must be one of [`OUTCOMES`]. Refused otherwise.
    pub outcome: String,
    /// Optional link to the quote that closed the sale on a `won`
    /// close. Ignored on `lost`.
    #[serde(default)]
    pub quote_id: Option<Uuid>,
}
