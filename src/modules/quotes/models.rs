//! Quote DTOs (PMS-672).

// These model enums expose `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API; they intentionally do not implement
// `std::str::FromStr` (which requires a `Result`). Mirrors `billing::models`.
#![allow(clippy::should_implement_trait)]

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Quote status; mirrors the CHECK constraint on `quotes.status`
/// (PMS-671).
///
/// The lifecycle splits internal sign-off from client sign-off:
///
/// ```text
/// draft -> submitted -> approved -> sent -> accepted -> converted
///                    \-> rejected        \-> declined
///                                        \-> expired
///   (any non-terminal state) -> cancelled
/// ```
///
/// `Submitted` / `Approved` / `Rejected` are the **internal** outcomes,
/// driven by the existing polymorphic approvals surface. `Accepted` /
/// `Declined` are the **client's** decision and are deliberately spelled
/// differently so a reader can always tell the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Draft,
    Submitted,
    Approved,
    Rejected,
    Sent,
    Accepted,
    Declined,
    Expired,
    Converted,
    Cancelled,
}

impl QuoteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Sent => "sent",
            Self::Accepted => "accepted",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Converted => "converted",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "submitted" => Some(Self::Submitted),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            "sent" => Some(Self::Sent),
            "accepted" => Some(Self::Accepted),
            "declined" => Some(Self::Declined),
            "expired" => Some(Self::Expired),
            "converted" => Some(Self::Converted),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// Statuses that accept no staff writes at all, not even a status
    /// change.
    ///
    /// Once a quote is `sent` the customer has seen the figures, and the
    /// states after that (`accepted`, `declined`, `expired`, `converted`)
    /// are decisions rather than drafts. `cancelled` is likewise
    /// terminal. Mirrors `InvoiceStatus::is_frozen`, which freezes an
    /// invoice once the customer can quote the totals back at you.
    ///
    /// Moving a quote out of one of these states is deliberately not an
    /// edit: `sent` is written by the PMS-673 send route, the client
    /// decision by the portal, and `converted` by the PMS-674 conversion.
    pub fn is_frozen(&self) -> bool {
        matches!(
            self,
            Self::Sent
                | Self::Accepted
                | Self::Declined
                | Self::Expired
                | Self::Converted
                | Self::Cancelled
        )
    }

    /// Statuses in which the quote's CONTENT (title, scope, lines, money)
    /// may still change.
    ///
    /// Narrower than the inverse of [`is_frozen`] on purpose. A quote in
    /// `submitted` or `approved` is not frozen outright, because the
    /// internal workflow still has to advance it, but its figures are
    /// what an approver is looking at or has already signed off on.
    /// Letting the content change underneath that approval would make the
    /// approval meaningless, so content edits are confined to the two
    /// states where the quote is still being worked up internally.
    pub fn allows_content_edit(&self) -> bool {
        matches!(self, Self::Draft | Self::Rejected)
    }

    /// Statuses a staff user may set directly through `PUT /quotes/{id}`.
    ///
    /// Excludes every status that belongs to another actor or route:
    /// `sent` (the PMS-673 send route), `accepted` / `declined` (the
    /// client, through the portal), `expired` (derived from
    /// `valid_until`), and `converted` (the PMS-674 conversion). Without
    /// this a staff user could forge a client's acceptance with a plain
    /// header update.
    pub fn is_staff_settable(&self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Submitted | Self::Approved | Self::Rejected | Self::Cancelled
        )
    }
}

/// Quote line type; mirrors the CHECK constraint on
/// `quote_lines.line_type` (PMS-671).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteLineType {
    Service,
    Product,
    Labour,
    Expense,
    Adjustment,
    Discount,
}

impl QuoteLineType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Product => "product",
            Self::Labour => "labour",
            Self::Expense => "expense",
            Self::Adjustment => "adjustment",
            Self::Discount => "discount",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "service" => Some(Self::Service),
            "product" => Some(Self::Product),
            "labour" => Some(Self::Labour),
            "expense" => Some(Self::Expense),
            "adjustment" => Some(Self::Adjustment),
            "discount" => Some(Self::Discount),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QuoteLineResponse {
    pub id: Uuid,
    pub line_type: QuoteLineType,
    pub description: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub total: Decimal,
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuoteResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub quote_number: Option<String>,
    pub company_id: Uuid,
    /// Display name of `company_id`, resolved on read so the client never
    /// has to show a raw UUID. Mirrors `InvoiceResponse::company_name`.
    /// `None` only if the company row is missing (e.g. deleted).
    pub company_name: Option<String>,
    pub billing_contact_id: Option<Uuid>,
    pub title: String,
    pub summary: Option<String>,
    /// The statement of work.
    pub description: Option<String>,
    pub status: QuoteStatus,
    pub valid_until: Option<NaiveDate>,
    pub subtotal: Decimal,
    pub tax_amount: Decimal,
    pub total: Decimal,
    pub currency: Option<String>,
    pub requested_by_id: Option<Uuid>,
    pub sent_at: Option<DateTime<Utc>>,
    /// Client sign-off, written by the PMS-673 portal routes.
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by_contact_id: Option<Uuid>,
    pub decision_notes: Option<String>,
    /// Set by the PMS-674 conversion.
    pub converted_project_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// `Some` on `GET /:id`, `None` on list rollups.
    pub lines: Option<Vec<QuoteLineResponse>>,
}

#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct QuoteFilter {
    pub company_id: Option<Uuid>,
    pub status: Option<String>,
    #[validate(length(max = 200))]
    pub q: Option<String>,
}

/// A line on create/update.
///
/// `quantity` and `unit_price` are intentionally signed, matching
/// `CreateInvoiceLineRequest` (PMS-306): a discount or adjustment line
/// carries a negative value, so a non-negative constraint would reject
/// legitimate lines.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct QuoteLineRequest {
    pub line_type: QuoteLineType,
    #[validate(length(min = 1, max = 1000))]
    pub description: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateQuoteRequest {
    pub company_id: Uuid,
    pub billing_contact_id: Option<Uuid>,
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    #[validate(length(max = 2000))]
    pub summary: Option<String>,
    pub description: Option<String>,
    pub valid_until: Option<NaiveDate>,
    #[validate(length(min = 3, max = 3))]
    pub currency: Option<String>,
    /// Optional tax on top of the line subtotal. There is deliberately no
    /// `subtotal` or `total` field: those are computed from `lines` and a
    /// client-supplied value would be ignored, so accepting one would only
    /// invite the caller to believe it mattered.
    pub tax_amount: Option<Decimal>,
    #[serde(default)]
    #[validate(nested)]
    pub lines: Vec<QuoteLineRequest>,
}

/// Header update. Every field is optional; omitted fields keep their
/// current value. `lines`, when present, REPLACES the whole line set
/// (mirrors `UpdateInvoiceRequest`).
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateQuoteRequest {
    pub billing_contact_id: Option<Uuid>,
    #[validate(length(min = 1, max = 255))]
    pub title: Option<String>,
    #[validate(length(max = 2000))]
    pub summary: Option<String>,
    pub description: Option<String>,
    pub valid_until: Option<NaiveDate>,
    #[validate(length(min = 3, max = 3))]
    pub currency: Option<String>,
    pub tax_amount: Option<Decimal>,
    /// Only the internal-workflow statuses are settable here. The client
    /// decision (`accepted` / `declined`) is written by the PMS-673 portal
    /// routes, and `converted` by the PMS-674 conversion, so neither can
    /// be forged through this endpoint.
    pub status: Option<QuoteStatus>,
    #[validate(nested)]
    pub lines: Option<Vec<QuoteLineRequest>>,
}
