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

    /// Statuses that disallow header / line edits. Once an invoice has been
    /// sent the customer can quote the totals back at you, so we freeze writes.
    ///
    /// PMS-953: correction goes through a credit note, and now actually can.
    /// This comment deferred that for long enough that `void` and
    /// `written_off` became statuses the model knew and no code path could
    /// reach; see `BillingService::create_credit_note`.
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
    /// Transportation reimbursement line (PMS-315). Sourced from
    /// `mileage_entries` by the invoice builder.
    Mileage,
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
            Self::Mileage => "mileage",
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
            "mileage" => Some(Self::Mileage),
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
    /// PMS-955: the catalog product this line sells, when it names one. The
    /// price is NOT read through this: `unit_price` below is what was charged,
    /// and it stays what was charged when the catalog changes.
    pub product_id: Option<Uuid>,
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
    /// PMS-953: the part of the total cancelled by issued credit notes.
    /// Derived alongside `amount_paid` by one recompute, never authored, so
    /// `balance_due` is `total - amount_paid - amount_credited` by
    /// construction.
    pub amount_credited: Decimal,
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
    /// PMS-955: optional link to the catalog. Validated against the caller's
    /// tenant and refused if the product is retired; it does not fill in the
    /// price, which the caller still states, so the line records what was
    /// actually charged.
    #[serde(default)]
    pub product_id: Option<Uuid>,
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
    /// PMS-990: optional. Omitted, the server derives it from the invoice
    /// date plus the net days of `payment_term_id`, or of the tenant's
    /// default term when none is named, or thirty days when the term names
    /// no count. Given, it is stored as given.
    pub due_date: Option<NaiveDate>,
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
    // PMS-990: a derived due date cannot precede the invoice date, so only a
    // given one is checked.
    if req.due_date.is_some_and(|due| due < req.invoice_date) {
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
    ///
    /// PMS-867: `min = 1` is the create-side rule, and it applies here for the
    /// same reason. `Some([])` used to delete every line and leave a zero-total
    /// invoice that `create_invoice` would have refused, and the same request
    /// can carry `status`, so it could be sent in that state. Omitting the key
    /// is how a caller leaves the existing lines alone; there is no edit that
    /// means "this invoice bills for nothing".
    #[validate(length(min = 1, message = "At least one line item is required"))]
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
    /// Payment amount. Must be strictly positive and at most 2 decimal places,
    /// and within the `DECIMAL(12, 2)` column magnitude. A zero or negative
    /// amount is rejected with a 422 field error rather than persisted, since
    /// it corrupts invoice balances and revenue reporting (PMS-373); an
    /// oversized value is likewise a 422 rather than a column overflow / 500
    /// (PMS-306).
    #[validate(custom(function = crate::utils::validation::validate_payment_amount))]
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
    /// Write-only secret (PMS-342): the stored credential is never returned.
    /// `true` when a config blob is stored for this gateway, so the client can
    /// render "configured" without seeing the plaintext. The secret stays
    /// decryptable strictly server-side for actual gateway calls; to change it,
    /// send a new `config` on upsert.
    pub configured: bool,
}

/// PMS-711: response to the portal "Pay Now" action. The SPA redirects the
/// browser to `checkout_url` (the provider's hosted checkout page).
#[derive(Debug, Clone, Serialize)]
pub struct PayInvoiceResponse {
    pub checkout_url: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertPaymentGatewayConfigRequest {
    pub provider: GatewayProvider,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default = "default_true")]
    pub is_test_mode: bool,
    /// Plaintext config; encrypted at rest before persisting. Write-only
    /// (PMS-342): omit (or send `null`) on update to keep the existing stored
    /// secret untouched; provide a value to replace it. Required when creating
    /// a gateway for the first time.
    #[serde(default)]
    pub config: Option<serde_json::Value>,
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
    #[validate(custom(function = crate::utils::validation::validate_tax_rate))]
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
    /// PMS-990: the number of days the term means, or `None` for a term that
    /// names no fixed count. Drives the derived due date; see
    /// `BillingService::resolve_due_date`.
    pub net_days: Option<i32>,
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
    /// PMS-990: days from the invoice date to the due date. Optional, because
    /// "On approval" is a legitimate term with no count; capped at ten years,
    /// because a larger value is a typo.
    #[validate(range(min = 0, max = 3650))]
    pub net_days: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use std::str::FromStr;

    fn one_line() -> CreateInvoiceLineRequest {
        CreateInvoiceLineRequest {
            line_type: InvoiceLineType::Service,
            product_id: None,
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
            due_date: Some(due_date),
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
    fn accepts_in_range_positive_payment_amount() {
        assert!(payment(Decimal::from_str("9999999999.99").unwrap())
            .validate()
            .is_ok());
        assert!(payment(Decimal::from_str("0.01").unwrap())
            .validate()
            .is_ok());
    }

    #[test]
    fn rejects_non_positive_payment_amount() {
        // PMS-373: zero and negative amounts must be a 422, not persisted.
        assert!(payment(Decimal::from_str("0").unwrap()).validate().is_err());
        assert!(payment(Decimal::from_str("-50.00").unwrap())
            .validate()
            .is_err());
    }

    #[test]
    fn rejects_over_precise_payment_amount() {
        // PMS-373: more than 2 decimal places would be silently rounded.
        assert!(payment(Decimal::from_str("50.001").unwrap())
            .validate()
            .is_err());
    }
}

// ============================================================================
// PMS-953: credit notes
// ============================================================================

/// Credit-note status; mirrors the CHECK constraint on `credit_notes.status`.
///
/// Two values and no editing. A credit note corrects an invoice that cannot be
/// edited, for the reason that the customer holds the original; the same
/// reasoning applies to the credit note itself, which the customer also holds.
/// Voiding is not an edit: every amount and every line stays exactly as issued,
/// and the credit simply stops counting against the invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditNoteStatus {
    Issued,
    Void,
}

impl CreditNoteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Void => "void",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "issued" => Some(Self::Issued),
            "void" => Some(Self::Void),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CreditNoteLineResponse {
    pub id: Uuid,
    pub line_type: InvoiceLineType,
    pub description: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub total: Decimal,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreditNoteResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub credit_note_number: String,
    pub company_id: Uuid,
    /// Display name of `company_id`, resolved on read so the client never has
    /// to show a raw UUID, exactly as `InvoiceResponse` does (PMS-186).
    pub company_name: Option<String>,
    pub invoice_id: Uuid,
    /// The corrected invoice's number, so a credit note reads as a document
    /// about a document rather than about a UUID.
    pub invoice_number: Option<String>,
    pub status: CreditNoteStatus,
    pub issue_date: NaiveDate,
    pub reason: String,
    pub subtotal: Decimal,
    pub tax_amount: Decimal,
    pub total: Decimal,
    pub currency: Option<String>,
    pub notes: Option<String>,
    pub created_by_id: Option<Uuid>,
    pub voided_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// `Some` on `GET /:id`, `None` on list rollups, like `InvoiceResponse`.
    pub lines: Option<Vec<CreditNoteLineResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateCreditNoteLineRequest {
    pub line_type: InvoiceLineType,
    #[validate(length(min = 1, max = 1000))]
    pub description: String,
    /// Required to be positive by `create_credit_note`, unlike
    /// `CreateInvoiceLineRequest`, where a negative line is a legitimate
    /// discount (PMS-306). The whole document is the negative here, so a
    /// negative line inside it is a charge hidden in a credit, and a check on
    /// the total alone would not catch one offset by a larger positive line.
    /// Enforced in the service rather than by a `validate` attribute because
    /// `validator`'s range check does not cover `Decimal`.
    pub quantity: Decimal,
    pub unit_price: Decimal,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateCreditNoteRequest {
    /// The invoice being corrected. Required: see the column comment in
    /// `migrations/122_credit_notes.sql` for why a standing account credit is
    /// not this document.
    pub invoice_id: Uuid,
    pub issue_date: Option<NaiveDate>,
    /// Required, and the first thing an auditor reads. A credit with no stated
    /// reason is the shape that makes an MSP's books unexplainable a year on.
    #[validate(length(min = 1, max = 2000))]
    pub reason: String,
    pub tax_amount: Option<Decimal>,
    #[validate(length(max = 3))]
    pub currency: Option<String>,
    pub notes: Option<String>,
    #[validate(length(min = 1, message = "At least one line item is required"))]
    #[validate(nested)]
    pub lines: Vec<CreateCreditNoteLineRequest>,
}

#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct CreditNoteFilter {
    pub company_id: Option<Uuid>,
    pub invoice_id: Option<Uuid>,
    #[validate(length(max = 20))]
    pub status: Option<String>,
}

// ============================================================================
// PMS-954: statements
// ============================================================================

/// What the caller asks for. There is no `status` filter and no free-text
/// search: a statement is an account, so leaving rows out on the caller's say-so
/// would produce a document that does not reconcile.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct StatementQuery {
    pub company_id: Uuid,
    /// Inclusive. Everything dated before this is folded into the opening
    /// balance rather than dropped.
    pub period_start: NaiveDate,
    /// Inclusive.
    pub period_end: NaiveDate,
}

/// One invoice on a statement. Deliberately not `InvoiceResponse`: a statement
/// shows what was charged and what is outstanding, and carrying the whole
/// invoice (lines included) would make a year-long statement enormous for
/// nothing.
#[derive(Debug, Clone, Serialize)]
pub struct StatementInvoiceLine {
    pub invoice_id: Uuid,
    pub invoice_number: String,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    pub status: InvoiceStatus,
    /// What was charged. The statement's arithmetic is in these figures, not
    /// in `invoices.balance_due`, which is a CURRENT number and would be wrong
    /// for any period that ended before the last payment landed.
    pub total: Decimal,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatementPaymentLine {
    pub payment_id: Uuid,
    pub payment_date: NaiveDate,
    pub amount: Decimal,
    pub payment_method: PaymentMethod,
    pub reference_number: Option<String>,
    /// The invoice it was applied to, when it was applied to one.
    pub invoice_number: Option<String>,
}

/// A refund is a payment running backwards: the client owes the money again.
/// Dated by `created_at`, because a provider refund carries no separate
/// business date the way a `payments` row does.
#[derive(Debug, Clone, Serialize)]
pub struct StatementRefundLine {
    pub refund_id: Uuid,
    pub refund_date: NaiveDate,
    pub amount: Decimal,
    pub invoice_number: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatementCreditLine {
    pub credit_note_id: Uuid,
    pub credit_note_number: String,
    pub issue_date: NaiveDate,
    pub total: Decimal,
    pub reason: String,
    pub invoice_number: Option<String>,
}

/// PMS-954: a client's account over a period.
///
/// Derived at read time and stored nowhere. A stored statement row would be a
/// second source of truth for numbers that already have one, and the two would
/// part company the first time a payment was backdated.
///
/// The consequence, worth stating rather than discovering: a statement is
/// reproducible but not immutable. Re-running the same period after a backdated
/// payment yields a different document, correctly. A statement that was SENT is
/// a different artefact, and it is the stored PDF (PMS-910), not a row here.
#[derive(Debug, Clone, Serialize)]
pub struct StatementResponse {
    pub company_id: Uuid,
    pub company_name: Option<String>,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    /// Everything before `period_start`, netted. Computed from the rows, never
    /// from a stored running total: a running total is a third place for the
    /// same number to live and the only one that can silently be wrong.
    pub opening_balance: Decimal,
    pub invoices: Vec<StatementInvoiceLine>,
    pub payments: Vec<StatementPaymentLine>,
    pub refunds: Vec<StatementRefundLine>,
    pub credit_notes: Vec<StatementCreditLine>,
    /// Sum of `invoices` above.
    pub total_invoiced: Decimal,
    /// Sum of `payments` above.
    pub total_paid: Decimal,
    /// Sum of `refunds` above.
    pub total_refunded: Decimal,
    /// Sum of `credit_notes` above.
    pub total_credited: Decimal,
    /// `opening_balance + total_invoiced + total_refunded - total_paid -
    /// total_credited`, and the tests assert exactly that rather than trusting
    /// the sentence.
    pub closing_balance: Decimal,
}

// ============================================================================
// PMS-955: product catalog
// ============================================================================

/// A sellable thing, priced per unit.
///
/// This is a price list, not an inventory system: there is no quantity on hand,
/// no purchasing and no vendor (PMS-821). It is also not a second home for
/// labour pricing, which is what `rate_cards` is: those are keyed on work type
/// and priced by the hour, and a product is priced by the unit.
#[derive(Debug, Clone, Serialize)]
pub struct ProductResponse {
    pub id: Uuid,
    pub sku: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub unit_price: Decimal,
    /// What one of it is: `each`, `hour`, `month`, `user`. Free text, because
    /// the list an MSP needs is theirs.
    pub unit: String,
    pub is_taxable: bool,
    /// Retirement is deactivation, never deletion: the documents that sold it
    /// still name it, and the database refuses to drop a referenced row.
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertProductRequest {
    /// Optional, and unique within the tenant when present.
    #[validate(length(min = 1, max = 64))]
    pub sku: Option<String>,
    /// Unique within the tenant, case-insensitively. Two catalog rows reading
    /// the same name with different prices is the confusion this table exists
    /// to remove, and it is invisible on screen.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub unit_price: Decimal,
    #[validate(length(min = 1, max = 30))]
    #[serde(default = "default_unit")]
    pub unit: String,
    #[serde(default = "default_true")]
    pub is_taxable: bool,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_unit() -> String {
    "each".to_string()
}

#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct ProductFilter {
    /// Omitted returns the whole catalog, active and retired, so an admin can
    /// see history; a picker passes `is_active=true`.
    pub is_active: Option<bool>,
    #[validate(length(max = 200))]
    pub q: Option<String>,
}
