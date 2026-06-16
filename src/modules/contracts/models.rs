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
#[validate(schema(function = validate_contract_date_range))]
pub struct CreateContractRequest {
    pub contract_number: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub company_id: Uuid,
    #[validate(custom(function = crate::utils::validation::validate_contract_type))]
    pub contract_type: String,
    #[serde(default = "default_draft")]
    #[validate(custom(function = crate::utils::validation::validate_contract_status))]
    pub status: String,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    #[serde(default)]
    pub auto_renew: bool,
    #[serde(default = "default_monthly")]
    #[validate(custom(function = crate::utils::validation::validate_billing_cycle))]
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

/// Cross-field check: a contract may not end before it starts (PMS-306). An
/// inverted range (`end_date < start_date`) was previously accepted and
/// persisted; reject it with a 422 at the request layer. A `None` `end_date`
/// (open-ended contract) is always valid.
fn validate_contract_date_range(
    req: &CreateContractRequest,
) -> Result<(), validator::ValidationError> {
    if let Some(end) = req.end_date {
        if end < req.start_date {
            // Re-key onto `end_date` so the form shows the message inline
            // rather than as a generic banner (PMS-364).
            return Err(crate::utils::validation::cross_field_error(
                "invalid_date_range",
                "end_date",
                "end_date must be on or after start_date",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateContractRequest {
    pub contract_number: Option<String>,
    pub name: Option<String>,
    #[validate(custom(function = crate::utils::validation::validate_contract_status))]
    pub status: Option<String>,
    pub end_date: Option<NaiveDate>,
    pub auto_renew: Option<bool>,
    #[validate(custom(function = crate::utils::validation::validate_billing_cycle))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn base_request(start: NaiveDate, end: Option<NaiveDate>) -> CreateContractRequest {
        CreateContractRequest {
            contract_number: None,
            name: "Test Contract".into(),
            company_id: Uuid::new_v4(),
            contract_type: "managed_services".into(),
            status: default_draft(),
            start_date: start,
            end_date: end,
            auto_renew: false,
            billing_cycle: default_monthly(),
            billing_amount: None,
            sla_id: None,
            signed_date: None,
            signed_by_contact_id: None,
            notes: None,
        }
    }

    #[test]
    fn rejects_inverted_contract_date_range() {
        // PMS-306: end before start must fail validation.
        let req = base_request(
            NaiveDate::from_ymd_opt(2026, 12, 31).unwrap(),
            Some(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()),
        );
        assert!(req.validate().is_err());
    }

    #[test]
    fn accepts_valid_and_open_ended_contract_ranges() {
        let ok = base_request(
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            Some(NaiveDate::from_ymd_opt(2026, 12, 31).unwrap()),
        );
        assert!(ok.validate().is_ok());
        // Equal dates are allowed (single-day contract).
        let same = base_request(
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            Some(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()),
        );
        assert!(same.validate().is_ok());
        // Open-ended contract (no end date) is allowed.
        let open = base_request(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), None);
        assert!(open.validate().is_ok());
    }

    #[test]
    fn create_rejects_out_of_set_status_and_billing_cycle() {
        // PMS-337: an out-of-set value must be a 422 at the request layer,
        // not a 500 from the DB CHECK constraint.
        let mut bad_status = base_request(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), None);
        bad_status.status = "pending".into();
        assert!(bad_status.validate().is_err());

        let mut bad_cycle = base_request(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), None);
        bad_cycle.billing_cycle = "weekly".into();
        assert!(bad_cycle.validate().is_err());
    }

    #[test]
    fn create_accepts_in_set_status_and_billing_cycle() {
        let mut req = base_request(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), None);
        req.status = "active".into();
        req.billing_cycle = "quarterly".into();
        assert!(req.validate().is_ok());
    }

    fn base_update() -> UpdateContractRequest {
        UpdateContractRequest {
            contract_number: None,
            name: None,
            status: None,
            end_date: None,
            auto_renew: None,
            billing_cycle: None,
            billing_amount: None,
            sla_id: None,
            signed_date: None,
            signed_by_contact_id: None,
            notes: None,
        }
    }

    #[test]
    fn update_validates_optional_status_and_billing_cycle() {
        // PMS-337: None skips the check; an out-of-set Some is rejected.
        assert!(base_update().validate().is_ok());

        let mut bad_status = base_update();
        bad_status.status = Some("pending".into());
        assert!(bad_status.validate().is_err());

        let mut bad_cycle = base_update();
        bad_cycle.billing_cycle = Some("weekly".into());
        assert!(bad_cycle.validate().is_err());

        let mut ok = base_update();
        ok.status = Some("renewed".into());
        ok.billing_cycle = Some("annually".into());
        assert!(ok.validate().is_ok());
    }
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
