//! Contracts DTOs.

// `BillingRule` exposes `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API, matching every other domain enum in this
// codebase; it intentionally does not implement `std::str::FromStr` (which
// requires a `Result`).
#![allow(clippy::should_implement_trait)]

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

/// PMS-1061: what a contact receives for a contract, on the dual-plane
/// reads. The MSP's `notes` are agent scratch and never reach the customer;
/// `sla_id`, `signed_by_contact_id`, `auto_renew` and the timestamps are
/// the MSP's own bookkeeping. The billing cycle and amount stay: the
/// customer signed them. This is the shape the retired portal router
/// served (`PortalContract`), which PMS-1025's sweep replaced with the
/// staff type by accident. Every key is always present (`null` when
/// unset) so the customer-facing shape is stable.
#[derive(Debug, Clone, Serialize)]
pub struct ContactContractResponse {
    pub id: Uuid,
    /// The caller's own company: what the session already says, never a
    /// foreign one, since the scope check runs before the projection.
    pub company_id: Uuid,
    pub contract_number: Option<String>,
    pub name: String,
    pub contract_type: String,
    pub status: String,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub billing_cycle: String,
    pub billing_amount: Option<Decimal>,
}

impl From<ContractResponse> for ContactContractResponse {
    fn from(c: ContractResponse) -> Self {
        Self {
            id: c.id,
            company_id: c.company_id,
            contract_number: c.contract_number,
            name: c.name,
            contract_type: c.contract_type,
            status: c.status,
            start_date: c.start_date,
            end_date: c.end_date,
            billing_cycle: c.billing_cycle,
            billing_amount: c.billing_amount,
        }
    }
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
    #[validate(length(min = 1, max = 255))]
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
    /// PMS-955: the catalog product this item sells, when it names one. The
    /// PRICE stays on the item: `unit_price` is what the contract agreed, and
    /// the invoice line the recurring worker writes copies it from here, not
    /// from the catalog, so editing the price list cannot re-price a signed
    /// contract.
    pub product_id: Option<Uuid>,
    /// PMS-956: what the recurring generator does with this item. `item_type`
    /// says what the item IS; this says whether it bills, and the two used to
    /// be one field, which is how a `product` item came to bill never.
    pub billing_rule: BillingRule,
    /// PMS-956: when a `once` item was billed, and `None` until it is. This is
    /// the per-item idempotency the period ledger cannot provide, since that is
    /// keyed on the period rather than the item.
    pub billed_at: Option<DateTime<Utc>>,
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
    /// PMS-955: optional link to the catalog. It does not fill in the price.
    #[serde(default)]
    pub product_id: Option<Uuid>,
    /// PMS-956: omitted, it is derived from `item_type` by
    /// [`BillingRule::derive`], which reproduces today's behaviour for the two
    /// types that already bill. State it to say something else: a licence sold
    /// on a contract is a `product` that should bill `every_period`.
    #[serde(default)]
    pub billing_rule: Option<BillingRule>,
}

/// PMS-956: what the recurring generator does with a contract item.
///
/// Three values, and none of them is a frequency. The period comes from the
/// contract's `billing_cycle`; this says only whether an item takes part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BillingRule {
    /// Billed on every one of the contract's periods. What `recurring_service`
    /// and `retainer` have always done.
    EveryPeriod,
    /// Billed on the next period that runs, and never again. A setup fee.
    Once,
    /// The generator never touches it; invoice it by hand if at all. The
    /// default, and the backfill target for every existing row that was not
    /// already billing, so nothing starts charging a client retroactively.
    #[default]
    Manual,
}

impl BillingRule {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EveryPeriod => "every_period",
            Self::Once => "once",
            Self::Manual => "manual",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "every_period" => Some(Self::EveryPeriod),
            "once" => Some(Self::Once),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }

    /// What an item bills when the caller does not say.
    ///
    /// One function rather than a rule spread across call sites, and it
    /// reproduces today's behaviour exactly for the two types that already
    /// bill, so an existing API client sees no change at all.
    ///
    /// `one_time` derives to `Once` because its name says so. `product` and
    /// `block_hours` derive to `Manual`: a product on a contract may be a
    /// monthly licence or a one-off box and the type cannot tell them apart,
    /// so the operator says which. That is still a change worth having, because
    /// `manual` is visible on the record and settable, where billing nothing
    /// was neither.
    pub fn derive(item_type: &str) -> Self {
        match item_type {
            "recurring_service" | "retainer" => Self::EveryPeriod,
            "one_time" => Self::Once,
            _ => Self::Manual,
        }
    }
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
    /// PMS-315: default per-mile reimbursement rate. A mileage entry with no
    /// explicit `rate_per_mile` inherits this from the tenant's default card.
    pub default_per_mile_rate: Option<Decimal>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertRateCardRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub is_default: bool,
    /// PMS-315: default per-mile reimbursement rate (NULL = unset).
    pub default_per_mile_rate: Option<Decimal>,
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
        bad_cycle.billing_cycle = "biweekly".into();
        assert!(bad_cycle.validate().is_err());
    }

    #[test]
    fn create_accepts_in_set_status_and_billing_cycle() {
        let mut req = base_request(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), None);
        req.status = "active".into();
        req.billing_cycle = "quarterly".into();
        assert!(req.validate().is_ok());

        // PMS-404: sub-month cycles are now accepted.
        let mut weekly = base_request(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), None);
        weekly.billing_cycle = "weekly".into();
        assert!(weekly.validate().is_ok());

        let mut bi_weekly = base_request(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(), None);
        bi_weekly.billing_cycle = "bi_weekly".into();
        assert!(bi_weekly.validate().is_ok());
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
        bad_cycle.billing_cycle = Some("biweekly".into());
        assert!(bad_cycle.validate().is_err());

        let mut ok = base_update();
        ok.status = Some("renewed".into());
        ok.billing_cycle = Some("annually".into());
        assert!(ok.validate().is_ok());

        // PMS-404: sub-month cycles are now accepted.
        let mut weekly = base_update();
        weekly.billing_cycle = Some("weekly".into());
        assert!(weekly.validate().is_ok());

        let mut bi_weekly = base_update();
        bi_weekly.billing_cycle = Some("bi_weekly".into());
        assert!(bi_weekly.validate().is_ok());
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
    /// PMS-1035: the contract item's `overage_rate` at the moment of the
    /// draw, `None` when the item names none. Carried separately from the
    /// amount because a missing rate is "bill the overage at the entry's
    /// own hourly rate", not "bill it at zero".
    pub overage_rate: Option<Decimal>,
    /// The balance row id that was debited (current period).
    pub balance_id: Uuid,
}

#[cfg(test)]
mod pms956_billing_rule_tests {
    use super::*;

    /// The compatibility rule, and the reason `derive` is one function rather
    /// than a match repeated at each call site.
    ///
    /// The two types that bill today must keep billing identically, or this
    /// change stops an MSP's recurring revenue the day it deploys. `one_time`
    /// gets the meaning its name has always claimed. Everything else is
    /// `Manual`, which bills nothing: a row written by a path that forgot must
    /// not start charging a client, because a missing charge is recoverable
    /// where a wrong one is a conversation.
    #[test]
    fn an_omitted_rule_reproduces_todays_behaviour() {
        assert_eq!(
            BillingRule::derive("recurring_service"),
            BillingRule::EveryPeriod
        );
        assert_eq!(BillingRule::derive("retainer"), BillingRule::EveryPeriod);
        assert_eq!(BillingRule::derive("one_time"), BillingRule::Once);
        // Not billed by the generator before this change, and not after it.
        assert_eq!(BillingRule::derive("product"), BillingRule::Manual);
        assert_eq!(BillingRule::derive("block_hours"), BillingRule::Manual);
        // A type this build does not know bills nothing rather than guessing.
        assert_eq!(BillingRule::derive("something_new"), BillingRule::Manual);
    }

    /// The default is the safe one, in the enum as well as in the column, so a
    /// value that arrives from neither the API nor the database still bills
    /// nothing.
    #[test]
    fn the_default_bills_nothing() {
        assert_eq!(BillingRule::default(), BillingRule::Manual);
        assert_eq!(BillingRule::from_str("nonsense"), None);
    }

    /// The wire form round-trips, so a stored value and a request body mean the
    /// same thing.
    #[test]
    fn every_value_round_trips_through_its_wire_form() {
        for rule in [
            BillingRule::EveryPeriod,
            BillingRule::Once,
            BillingRule::Manual,
        ] {
            assert_eq!(BillingRule::from_str(rule.as_str()), Some(rule));
        }
    }
}
