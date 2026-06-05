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
    pub billing_contact_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub status: InvoiceStatus,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    pub payment_terms: Option<String>,
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
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub ticket_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateInvoiceRequest {
    pub company_id: Uuid,
    pub billing_contact_id: Option<Uuid>,
    pub contract_id: Option<Uuid>,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    #[validate(length(max = 20))]
    pub payment_terms: Option<String>,
    pub tax_amount: Option<Decimal>,
    pub discount_amount: Option<Decimal>,
    #[validate(length(max = 3))]
    pub currency: Option<String>,
    pub notes: Option<String>,
    pub po_number: Option<String>,
    #[validate(length(min = 1, message = "At least one line item is required"))]
    pub lines: Vec<CreateInvoiceLineRequest>,
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
    pub company_id: Uuid,
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
