//! MAPPS-1100 scaffold: Rust types mirroring the `vendors`, `bills`,
//! `expenses` tables from migration 279.
//!
//! Pure data types. No service methods, no construction, no behavior.
//! The next phase of MAPPS-1100 reads sqlx rows into these and writes
//! them back out; the shapes here are the contract the first endpoint's
//! request / response types derive from.
//!
//! Money is minor units (cents) throughout, matching the schema and the
//! existing `invoices.subtotal_minor` convention (PMS-1028).

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

/// A vendor the MSP buys from. Tenant-scoped; separate from `companies`
/// (which is the MSP's customers) on purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Vendor {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub account_number: Option<String>,
    pub default_currency: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A category applied to a bill line or an expense line to classify
/// what the money went to. One taxonomy per tenant; a tenant seeds its
/// own set rather than inheriting a global list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct ExpenseCategory {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// The lifecycle of a bill. Stored as a text column with a CHECK; the
/// enum here is the Rust-side mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillStatus {
    Draft,
    Approved,
    Paid,
    Void,
}

impl BillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Approved => "approved",
            Self::Paid => "paid",
            Self::Void => "void",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "draft" => Some(Self::Draft),
            "approved" => Some(Self::Approved),
            "paid" => Some(Self::Paid),
            "void" => Some(Self::Void),
            _ => None,
        }
    }
}

/// A bill from a vendor: what the MSP owes.
///
/// `status` is modelled as the enum above but stored as text; the sqlx
/// derive carries the text form and a later phase's service converts.
/// `external_provider` / `external_bill_id` carry the MAPPS-1099-posture
/// pointer for a bill issued by Xero or QuickBooks on behalf of a
/// tenant that delegated the capability; both NULL on a Mokosh-held
/// bill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Bill {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub vendor_id: Uuid,
    pub bill_number: Option<String>,
    pub issue_date: NaiveDate,
    pub due_date: Option<NaiveDate>,
    pub currency: String,
    pub subtotal_minor: i64,
    pub tax_minor: i64,
    pub total_minor: i64,
    pub paid_minor: i64,
    /// Text form of [`BillStatus`]; converted by the service.
    pub status: String,
    pub notes: Option<String>,
    pub external_provider: Option<String>,
    pub external_bill_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One line of a bill. Quantities are hundredths (so 1.25 = 125) to
/// match the existing invoice-line shape; prices + totals are minor
/// units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct BillLine {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub bill_id: Uuid,
    pub category_id: Option<Uuid>,
    pub description: String,
    pub quantity_hundredths: i64,
    pub unit_price_minor: i64,
    pub tax_minor: i64,
    pub total_minor: i64,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

/// What narrows `GET /bills` (PMS-1539).
///
/// The shape `InvoiceFilter` set for receivables, with the two fields a
/// bills list needs and none it does not: `status` is one of the four the
/// CHECK allows, and a value outside it answers an empty page rather than
/// a 400, which is what `InvoiceFilter` does with an unknown status.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
pub struct BillFilter {
    #[validate(length(max = 20))]
    pub status: Option<String>,
    #[validate(length(max = 200))]
    pub q: Option<String>,
}

/// What narrows `GET /expenses` (PMS-1539). The claims half of
/// [`BillFilter`]; `status` is one of the five an expense moves through.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
pub struct ExpenseFilter {
    #[validate(length(max = 20))]
    pub status: Option<String>,
    #[validate(length(max = 200))]
    pub q: Option<String>,
}

/// One payment the MSP made against a bill (PMS-1536).
///
/// Money leaving, in minor units like everything else in this subsystem.
/// The rows are the record of WHAT was paid and WHEN, which a vendor
/// statement has to be reconciled against; `bills.paid_minor` is the
/// running total derived from them and has exactly one writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct BillPayment {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub bill_id: Uuid,
    pub paid_on: NaiveDate,
    pub amount_minor: i64,
    pub payment_method: String,
    pub reference: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// The lifecycle of an expense claim. `reimbursed` is terminal and
/// immutable; a correction is a reversing expense per the MAPPS-1100
/// scoping (same pattern as invoice amendments in PMS-1334).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpenseStatus {
    Draft,
    Submitted,
    Approved,
    Reimbursed,
    Rejected,
}

impl ExpenseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Approved => "approved",
            Self::Reimbursed => "reimbursed",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "draft" => Some(Self::Draft),
            "submitted" => Some(Self::Submitted),
            "approved" => Some(Self::Approved),
            "reimbursed" => Some(Self::Reimbursed),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// An expense: what one of the MSP's own people spent. Approval is a
/// Finance role action (modeled against RequireFinance when the service
/// lands); reimbursement is terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Expense {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub incurred_on: NaiveDate,
    pub currency: String,
    pub subtotal_minor: i64,
    pub tax_minor: i64,
    pub total_minor: i64,
    /// Text form of [`ExpenseStatus`]; converted by the service.
    pub status: String,
    pub approver_id: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub reimbursed_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub external_provider: Option<String>,
    pub external_expense_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One line of an expense claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct ExpenseLine {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub expense_id: Uuid,
    pub category_id: Option<Uuid>,
    pub description: String,
    pub amount_minor: i64,
    pub tax_minor: i64,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both status enums round-trip through their stored spelling, so
    /// the eventual service converting back from a sqlx text column
    /// cannot land on a case the enum does not understand without the
    /// test failing.
    #[test]
    fn bill_status_round_trips_through_parse() {
        for status in [
            BillStatus::Draft,
            BillStatus::Approved,
            BillStatus::Paid,
            BillStatus::Void,
        ] {
            assert_eq!(BillStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(BillStatus::parse("unknown"), None);
        assert_eq!(BillStatus::parse(""), None);
    }

    #[test]
    fn expense_status_round_trips_through_parse() {
        for status in [
            ExpenseStatus::Draft,
            ExpenseStatus::Submitted,
            ExpenseStatus::Approved,
            ExpenseStatus::Reimbursed,
            ExpenseStatus::Rejected,
        ] {
            assert_eq!(ExpenseStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(ExpenseStatus::parse("unknown"), None);
        assert_eq!(ExpenseStatus::parse(""), None);
    }

    /// Pin the stored string set in a shape that matches migration 279's
    /// CHECK. A new value added to the enum without widening the CHECK
    /// would quietly refuse inserts; a new value added to the CHECK
    /// without the enum would deserialise as `None` and the service
    /// could not act on it.
    #[test]
    fn status_strings_match_the_migration_check() {
        const MIGRATION: &str = include_str!("../../../migrations/279_expenses_subsystem.sql");
        for status in ["draft", "approved", "paid", "void"] {
            assert!(
                MIGRATION.contains(&format!("'{status}'")),
                "bill status {status:?} is not in the CHECK"
            );
        }
        for status in ["draft", "submitted", "approved", "reimbursed", "rejected"] {
            assert!(
                MIGRATION.contains(&format!("'{status}'")),
                "expense status {status:?} is not in the CHECK"
            );
        }
    }
}
