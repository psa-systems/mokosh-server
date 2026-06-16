//! Billing DTOs.

// These model enums expose `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API; they intentionally do not implement
// `std::str::FromStr` (which requires a `Result`).
#![allow(clippy::should_implement_trait)]

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Invoice status; mirrors the CHECK constraint on `invoices.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Draft,
    Pending,
    Sent,
    Paid,
    PartiallyPaid,
    Void,
    WrittenOff,
}

impl InvoiceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Paid => "paid",
            Self::PartiallyPaid => "partially_paid",
            Self::Void => "void",
            Self::WrittenOff => "written_off",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "pending" => Some(Self::Pending),
            "sent" => Some(Self::Sent),
            "paid" => Some(Self::Paid),
            "partially_paid" => Some(Self::PartiallyPaid),
            "void" => Some(Self::Void),
            "written_off" => Some(Self::WrittenOff),
            _ => None,
        }
    }

    /// Statuses that disallow header / line edits. Once an invoice has
    /// been sent the customer can quote the totals back at you, so we
    /// freeze writes; correction goes through a credit note (out of
    /// scope here).
    pub fn is_frozen(&self) -> bool {
        matches!(
            self,
            Self::Sent | Self::Paid | Self::PartiallyPaid | Self::Void | Self::WrittenOff
        )
    }
}

/// Invoice line type; mirrors the CHECK constraint on `invoice_lines.line_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceLineType {
    Service,
    Product,
    TimeEntry,
    Adjustment,
    Tax,
    Discount,
}

impl InvoiceLineType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Product => "product",
            Self::TimeEntry => "time_entry",
            Self::Adjustment => "adjustment",
            Self::Tax => "tax",
            Self::Discount => "discount",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "service" => Some(Self::Service),
            "product" => Some(Self::Product),
            "time_entry" => Some(Self::TimeEntry),
            "adjustment" => Some(Self::Adjustment),
            "tax" => Some(Self::Tax),
            "discount" => Some(Self::Discount),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InvoiceLineResponse {
    pub id: Uuid,
    pub line_type: InvoiceLineType,
    pub description: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub total: Decimal,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvoiceResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub invoice_number: String,
    pub company_id: Uuid,
    /// Display name of `company_id`, resolved on read so the client never
    /// has to show a raw UUID (PMS-186). `None` only if the company row is
    /// missing (e.g. deleted).
    pub company_name: Option<String>,
    pub billing_contact_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub status: InvoiceStatus,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    /// Legacy free-text terms, kept for one release (PMS-333). Prefer
    /// `payment_term_id`, which references the `payment_terms` lookup.
    pub payment_terms: Option<String>,
    /// FK into the tenant-scoped `payment_terms` lookup (PMS-333). `None` for
    /// invoices whose legacy `payment_terms` string had no matching lookup row.
    pub payment_term_id: Option<Uuid>,
    /// Joined name of `payment_term_id`, resolved on read so the client renders
    /// the term without a second fetch. `None` when there is no term linked.
    pub payment_term_name: Option<String>,
    pub subtotal: Decimal,
    pub tax_amount: Decimal,
    pub discount_amount: Decimal,
    pub total: Decimal,
    pub amount_paid: Decimal,
    pub balance_due: Decimal,
    pub currency: Option<String>,
    pub notes: Option<String>,
    pub po_number: Option<String>,
    pub sent_at: Option<DateTime<Utc>>,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// `Some` on `GET /:id`, `None` on list rollups.
    pub lines: Option<Vec<InvoiceLineResponse>>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct InvoiceFilter {
    pub company_id: Option<Uuid>,
    pub status: Option<String>,
    pub contract_id: Option<Uuid>,
    #[validate(length(max = 200))]
    pub q: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateInvoiceLineRequest {
    pub line_type: InvoiceLineType,
    #[validate(length(min = 1, max = 1000))]
    pub description: String,
    /// `quantity` and `unit_price` are intentionally signed (PMS-306): a
    /// discount or credit line carries a negative value, so a non-negative
    /// constraint would reject legitimate adjustments. Sign is allowed by
    /// design; only the column magnitude matters at the DB layer.
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[validate(schema(function = validate_invoice_date_range))]
pub struct CreateInvoiceRequest {
    pub company_id: Uuid,
    pub billing_contact_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    #[validate(length(max = 20))]
    pub payment_terms: Option<String>,
    /// Optional FK into the tenant's `payment_terms` lookup (PMS-333). The
    /// service validates it belongs to the caller's tenant.
    pub payment_term_id: Option<Uuid>,
    pub tax_amount: Option<Decimal>,
    pub discount_amount: Option<Decimal>,
    #[validate(length(max = 3))]
    pub currency: Option<String>,
    pub notes: Option<String>,
    pub po_number: Option<String>,
    #[validate(length(min = 1, message = "At least one line item is required"))]
    pub lines: Vec<CreateInvoiceLineRequest>,
}

/// Cross-field check: an invoice's `due_date` may not fall before its
/// `invoice_date` (PMS-306). The inverted range was previously accepted;
/// reject it with a 422 instead of persisting a due-before-issue invoice.
fn validate_invoice_date_range(
    req: &CreateInvoiceRequest,
) -> Result<(), validator::ValidationError> {
    if req.due_date < req.invoice_date {
        // Re-key onto `due_date` so the form shows the message inline
        // rather than as a generic banner (PMS-364).
        return Err(crate::utils::validation::cross_field_error(
            "invalid_date_range",
            "due_date",
            "due_date must be on or after invoice_date",
        ));
    }
    Ok(())
}

/// PMS-33 core: generate an invoice from a company's billable time
/// entries. When `time_entry_ids` is `None`, every eligible entry for
/// the company is swept in; when `Some`, only the listed ids (that are
/// still eligible) are billed.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateInvoiceFromTimeEntriesRequest {
    pub company_id: Uuid,
    pub billing_contact_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub invoice_date: Option<NaiveDate>,
    pub due_date: Option<NaiveDate>,
    #[validate(length(max = 20))]
    pub payment_terms: Option<String>,
    #[validate(length(max = 3))]
    pub currency: Option<String>,
    pub notes: Option<String>,
    pub po_number: Option<String>,
    /// Restrict to these entries. `None` bills every eligible entry.
    pub time_entry_ids: Option<Vec<Uuid>>,
}

/// Header-only update. To replace line items, send `lines = Some(...)`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateInvoiceRequest {
    pub billing_contact_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub invoice_date: Option<NaiveDate>,
    pub due_date: Option<NaiveDate>,
    #[validate(length(max = 20))]
    pub payment_terms: Option<String>,
    /// Optional FK into the tenant's `payment_terms` lookup (PMS-333),
    /// preserved on omit; an explicit value re-links and is tenant-validated.
    pub payment_term_id: Option<Uuid>,
    pub tax_amount: Option<Decimal>,
    pub discount_amount: Option<Decimal>,
    pub notes: Option<String>,
    pub po_number: Option<String>,
    /// `Some` -> replace all lines (transactional). `None` -> leave alone.
    pub lines: Option<Vec<CreateInvoiceLineRequest>>,
    /// Transition status. Same set as the schema CHECK constraint.
    pub status: Option<InvoiceStatus>,
}

// ============================================================================
// Payments
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethod {
    Check,
    CreditCard,
    Ach,
    Wire,
    Cash,
    Other,
}

impl PaymentMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::CreditCard => "credit_card",
            Self::Ach => "ach",
            Self::Wire => "wire",
            Self::Cash => "cash",
            Self::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "check" => Some(Self::Check),
            "credit_card" => Some(Self::CreditCard),
            "ach" => Some(Self::Ach),
            "wire" => Some(Self::Wire),
            "cash" => Some(Self::Cash),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub invoice_id: Option<Uuid>,
    /// Human invoice number of `invoice_id`, resolved on read (PMS-186), so
    /// the client shows the number instead of the invoice UUID. `None` for
    /// an unapplied payment or a missing invoice.
    pub invoice_number: Option<String>,
    pub company_id: Uuid,
    /// Display name of `company_id`, resolved on read (PMS-186). `None`
    /// only if the company row is missing.
    pub company_name: Option<String>,
    pub payment_date: NaiveDate,
    pub amount: Decimal,
    pub payment_method: PaymentMethod,
    pub reference_number: Option<String>,
    pub gateway_transaction_id: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreatePaymentRequest {
    pub invoice_id: Option<Uuid>,
    pub company_id: Uuid,
    pub payment_date: NaiveDate,
    /// Payment amount. Bounded to the `DECIMAL(12, 2)` column magnitude so an
    /// oversized value returns a 422 rather than overflowing the column and
    /// surfacing as a 500 (PMS-306). The sign is intentionally NOT constrained:
    /// negative amounts represent refunds / reversals and are allowed by
    /// design, so only the magnitude is validated here.
    #[validate(custom(function = crate::utils::validation::validate_money_amount))]
    pub amount: Decimal,
    pub payment_method: PaymentMethod,
    pub reference_number: Option<String>,
    pub gateway_transaction_id: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct PaymentFilter {
    pub invoice_id: Option<Uuid>,
    pub company_id: Option<Uuid>,
}

// ============================================================================
// Payment gateway configs
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayProvider {
    Stripe,
    AuthorizeNet,
    Paypal,
}

impl GatewayProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stripe => "stripe",
            Self::AuthorizeNet => "authorize_net",
            Self::Paypal => "paypal",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "stripe" => Some(Self::Stripe),
            "authorize_net" => Some(Self::AuthorizeNet),
            "paypal" => Some(Self::Paypal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymentGatewayConfigResponse {
    pub id: Uuid,
    pub provider: GatewayProvider,
    pub is_active: bool,
    pub is_test_mode: bool,
    /// The decrypted plaintext config (typically JSON). Never serialise
    /// the raw column blob.
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertPaymentGatewayConfigRequest {
    pub provider: GatewayProvider,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default = "default_true")]
    pub is_test_mode: bool,
    /// Plaintext config; encrypted at rest before persisting.
    pub config: serde_json::Value,
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Tax rates
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TaxRateResponse {
    pub id: Uuid,
    pub name: String,
    pub rate: Decimal,
    pub is_default: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertTaxRateRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub rate: Decimal,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

// ============================================================================
// Payment terms (PMS-333) - tenant-scoped lookup, mirrors work_types.
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct PaymentTermResponse {
    pub id: Uuid,
    pub name: String,
    pub is_default: bool,
    pub is_active: bool,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertPaymentTermRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub sort_order: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use std::str::FromStr;

    fn one_line() -> CreateInvoiceLineRequest {
        CreateInvoiceLineRequest {
            line_type: InvoiceLineType::Service,
            description: "Work".into(),
            quantity: Decimal::from(1),
            unit_price: Decimal::from(100),
            ticket_id: None,
            project_id: None,
            sort_order: 0,
        }
    }

    fn invoice(invoice_date: NaiveDate, due_date: NaiveDate) -> CreateInvoiceRequest {
        CreateInvoiceRequest {
            company_id: Uuid::new_v4(),
            billing_contact_id: None,
            contract_id: None,
            invoice_date,
            due_date,
            payment_terms: None,
            payment_term_id: None,
            tax_amount: None,
            discount_amount: None,
            currency: None,
            notes: None,
            po_number: None,
            lines: vec![one_line()],
        }
    }

    fn payment(amount: Decimal) -> CreatePaymentRequest {
        CreatePaymentRequest {
            invoice_id: None,
            company_id: Uuid::new_v4(),
            payment_date: NaiveDate::from_ymd_opt(2026, 6, 14).unwrap(),
            amount,
            payment_method: PaymentMethod::Check,
            reference_number: None,
            gateway_transaction_id: None,
            notes: None,
        }
    }

    #[test]
    fn rejects_due_before_invoice_date() {
        // PMS-306: due_date before invoice_date must fail.
        let req = invoice(
            NaiveDate::from_ymd_opt(2026, 6, 14).unwrap(),
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
        );
        assert!(req.validate().is_err());
    }

    #[test]
    fn accepts_valid_invoice_date_range() {
        let req = invoice(
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2026, 2, 1).unwrap(),
        );
        assert!(req.validate().is_ok());
        // Same-day (due == issue) is allowed.
        let same = invoice(
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
        );
        assert!(same.validate().is_ok());
    }

    #[test]
    fn rejects_oversized_payment_amount() {
        // PMS-306: 1e15 overflows DECIMAL(12, 2); must be a 422, not a 500.
        let req = payment(Decimal::from_str("1000000000000000").unwrap());
        assert!(req.validate().is_err());
    }

    #[test]
    fn accepts_in_range_and_signed_payment_amount() {
        assert!(payment(Decimal::from_str("9999999999.99").unwrap())
            .validate()
            .is_ok());
        // Negative amounts (refunds) are intentionally allowed.
        assert!(payment(Decimal::from_str("-250.00").unwrap())
            .validate()
            .is_ok());
    }
}
