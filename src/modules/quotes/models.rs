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

    /// Statuses a client contact may see through the portal (PMS-673).
    ///
    /// Everything before `sent` is internal working state: a `draft` or
    /// `submitted` quote is not finished, and `approved` only means staff
    /// cleared it to go out. `rejected` and `cancelled` were killed
    /// internally, so showing them would leak a negotiation the customer
    /// was never part of. What remains is the quote as issued and whatever
    /// became of it.
    pub fn is_client_visible(&self) -> bool {
        matches!(
            self,
            Self::Sent | Self::Accepted | Self::Declined | Self::Expired | Self::Converted
        )
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
    /// PMS-1038: counts toward the taxable subtotal. Stored per line.
    pub is_taxable: bool,
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
    /// PMS-1038: the rate `tax_amount` is derived from, frozen on the quote.
    /// `None` means the amount was given and `recompute_totals` leaves it.
    pub tax_rate_id: Option<Uuid>,
    pub tax_rate: Option<Decimal>,
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
    /// PMS-1038: default taxable.
    #[serde(default = "default_true")]
    pub is_taxable: bool,
}

fn default_true() -> bool {
    true
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
    /// PMS-1038: the rate to derive the tax from; absent, the tenant's
    /// default. Ignored when `tax_amount` is given.
    pub tax_rate_id: Option<Uuid>,
    #[serde(default)]
    #[validate(nested)]
    pub lines: Vec<QuoteLineRequest>,
}

/// Body of `POST /portal/quotes/{id}/accept|decline` (PMS-673).
///
/// Notes are optional: a client accepting rarely has anything to add,
/// while a decline usually does. There is deliberately no status field;
/// the route decides the outcome, so the client cannot post its way into
/// an arbitrary state.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
pub struct PortalQuoteDecisionRequest {
    #[validate(length(max = 2000))]
    pub notes: Option<String>,
}

/// Body of `POST /quotes/{id}/convert` (PMS-674).
///
/// Carries only the fields a quote cannot supply. Name, scope, client,
/// and budget are mapped from the quote itself, so they are deliberately
/// absent here: letting the caller restate them would allow the project
/// to disagree with the quote the client signed.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
#[validate(schema(function = validate_project_dates))]
pub struct ConvertQuoteRequest {
    pub project_manager_id: Option<Uuid>,
    pub start_date: Option<NaiveDate>,
    pub target_end_date: Option<NaiveDate>,
    /// Defaults to `fixed_price` when omitted: an accepted quote IS a
    /// fixed price the client agreed to, so inheriting the `projects`
    /// column default of `time_and_materials` would quietly contradict
    /// what was signed.
    #[validate(custom(function = validate_billing_method))]
    pub billing_method: Option<String>,
    pub budget_hours: Option<Decimal>,
}

fn validate_billing_method(value: &str) -> Result<(), validator::ValidationError> {
    // Mirrors the CHECK on `projects.billing_method`; rejected here so a
    // bad value is a 422 with a field name rather than a 500 from the
    // database.
    match value {
        "fixed_price" | "time_and_materials" | "not_billable" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_billing_method")),
    }
}

fn validate_project_dates(req: &ConvertQuoteRequest) -> Result<(), validator::ValidationError> {
    if let (Some(start), Some(end)) = (req.start_date, req.target_end_date) {
        if end < start {
            return Err(validator::ValidationError::new(
                "target_end_date_before_start_date",
            ));
        }
    }
    Ok(())
}

/// The client's sign-off, as handed from the portal route to the service
/// (PMS-673).
///
/// Bundled rather than passed as loose parameters so the identity fields
/// travel together: `company_id` is the scope check and `contact_id` is
/// the actor recorded on the row, and separating them at a call site is
/// how you end up recording the wrong one.
#[derive(Debug, Clone)]
pub struct ClientDecision {
    /// The deciding contact's company. The service refuses a quote that
    /// belongs to a different company.
    pub company_id: Uuid,
    /// Written to `quotes.decided_by_contact_id`.
    pub contact_id: Uuid,
    /// `true` accepts, `false` declines.
    pub accept: bool,
    pub notes: Option<String>,
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
    /// PMS-1038: naming a rate re-derives the tax on every line change from
    /// then on; giving `tax_amount` clears the rate and keeps the amount.
    pub tax_rate_id: Option<Uuid>,
    /// Only the internal-workflow statuses are settable here. The client
    /// decision (`accepted` / `declined`) is written by the PMS-673 portal
    /// routes, and `converted` by the PMS-674 conversion, so neither can
    /// be forged through this endpoint.
    pub status: Option<QuoteStatus>,
    #[validate(nested)]
    pub lines: Option<Vec<QuoteLineRequest>>,
}
