//! Billing status vocabulary.
//!
//! The enums a billing document's wire format is written in, and the rules
//! over them that both sides need. PMS-1375 moved them here because the
//! client was holding a status as a `String` and re-implementing
//! [`InvoiceStatus::is_frozen`] in string literals, which is the drift
//! MAPPS-383 removed from time-tracking: nothing fails to compile when the
//! server's vocabulary moves.
//!
//! The response and request structs deliberately stay in
//! `mokosh_server::modules::billing::models`. Every billing page declares the
//! documented subset it renders beside the fetch that reads it, so there is
//! no second consumer for them here, and `overdue_days` stays server-side
//! because PMS-1037 derives overdue in the TENANT's day and MAPPS-728 has the
//! client render what it is told rather than compute from the browser clock.

// These model enums expose `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API; they intentionally do not implement
// `std::str::FromStr` (which requires a `Result`).
#![allow(clippy::should_implement_trait)]

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethod {
    Check,
    CreditCard,
    Ach,
    Wire,
    Cash,
    /// PMS-1235: a gateway-confirmed PayPal payment. Distinct from
    /// `CreditCard`, which `record_gateway_payment` used to record for every
    /// gateway regardless of which one actually took the payment.
    Paypal,
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
            Self::Paypal => "paypal",
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
            "paypal" => Some(Self::Paypal),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

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
