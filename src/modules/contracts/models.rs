//! Contracts DTOs.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct ContractResponse {
    pub id: Uuid,
    pub contract_number: Option<String>,
    pub name: String,
    pub company_id: Uuid,
    pub contract_type: String,
    pub status: String,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub auto_renew: bool,
    pub billing_cycle: String,
    pub billing_amount: Option<Decimal>,
    pub sla_id: Option<Uuid>,
    pub signed_date: Option<NaiveDate>,
    pub signed_by_contact_id: Option<Uuid>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct ContractFilter {
    pub company_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub contract_type: Option<String>,
    #[validate(length(max = 100))]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateContractRequest {
    pub contract_number: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub company_id: Uuid,
    #[validate(custom(function = crate::utils::validation::validate_contract_type))]
    pub contract_type: String,
    #[serde(default = "default_draft")]
    pub status: String,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    #[serde(default)]
    pub auto_renew: bool,
    #[serde(default = "default_monthly")]
    pub billing_cycle: String,
    pub billing_amount: Option<Decimal>,
    pub sla_id: Option<Uuid>,
    pub signed_date: Option<NaiveDate>,
    pub signed_by_contact_id: Option<Uuid>,
    pub notes: Option<String>,
}

fn default_draft() -> String {
    "draft".into()
}
fn default_monthly() -> String {
    "monthly".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateContractRequest {
    pub contract_number: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub end_date: Option<NaiveDate>,
    pub auto_renew: Option<bool>,
    pub billing_cycle: Option<String>,
    pub billing_amount: Option<Decimal>,
    pub sla_id: Option<Uuid>,
    pub signed_date: Option<NaiveDate>,
    pub signed_by_contact_id: Option<Uuid>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractItemResponse {
    pub id: Uuid,
    pub contract_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub item_type: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub total_price: Decimal,
    pub billing_frequency: String,
    pub work_type_id: Option<Uuid>,
    pub included_hours: Option<Decimal>,
    pub overage_rate: Option<Decimal>,
    pub rollover_enabled: bool,
    pub max_rollover_hours: Option<Decimal>,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertContractItemRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub item_type: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    #[serde(default = "default_monthly")]
    pub billing_frequency: String,
    pub work_type_id: Option<Uuid>,
    pub included_hours: Option<Decimal>,
    pub overage_rate: Option<Decimal>,
    #[serde(default)]
    pub rollover_enabled: bool,
    pub max_rollover_hours: Option<Decimal>,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractHourBalanceResponse {
    pub id: Uuid,
    pub contract_id: Uuid,
    pub contract_item_id: Uuid,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub hours_included: Decimal,
    pub hours_used: Decimal,
    pub hours_remaining: Decimal,
    pub rollover_hours: Decimal,
}

#[derive(Debug, Clone, Serialize)]
pub struct RateCardResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertRateCardRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RateCardItemResponse {
    pub id: Uuid,
    pub rate_card_id: Uuid,
    pub work_type_id: Uuid,
    pub hourly_rate: Decimal,
    pub after_hours_rate: Option<Decimal>,
    pub emergency_rate: Option<Decimal>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertRateCardItemRequest {
    pub work_type_id: Uuid,
    pub hourly_rate: Decimal,
    pub after_hours_rate: Option<Decimal>,
    pub emergency_rate: Option<Decimal>,
}

/// Outcome of [`ContractsService::consume_hours`].
///
/// `hours_applied` is the portion of the requested hours drawn from the
/// period's remaining included allotment. `overage_hours` is the
/// remainder that fell past the included allotment; it is billed at the
/// contract item's `overage_rate`, giving `overage_amount`. When the
/// requested hours fit entirely within the allotment `overage_hours` and
/// `overage_amount` are both zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsumeOutcome {
    /// Hours drawn from the included allotment for this period.
    pub hours_applied: Decimal,
    /// Hours past the included allotment, billed as overage.
    pub overage_hours: Decimal,
    /// `overage_hours * overage_rate` (zero when no overage / no rate).
    pub overage_amount: Decimal,
    /// The balance row id that was debited (current period).
    pub balance_id: Uuid,
}
