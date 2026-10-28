//! MAPPS-1099 Phase 1 groundwork for the invoice-issuer dispatch.
//!
//! Phase 1 (this module + the schema it leans on) names the provider
//! vocabulary that every later phase shares. The actual OAuth 2.0 clients
//! for Xero and QuickBooks land in Phase 1b and Phase 1c; the
//! `InvoiceIssuer` trait that routes between the local path and an
//! external provider lands in Phase 2 (per MAPPS-1099). None of that
//! writes code the HTTP surface advertises today, so this module stays
//! vocabulary-only on purpose: no stub methods, no NotImplemented returns,
//! and no handler mounts.
//!
//! The schema half (migration 278) added `external_provider`,
//! `external_invoice_id` and `external_number` to `invoices`. Phase 1
//! here surfaces them through `InvoiceResponse` so a reader can
//! distinguish a Mokosh-issued row from a delegated one the moment the
//! first delegated row exists.

use serde::{Deserialize, Serialize};

/// The set of external invoice-issuer providers Mokosh will delegate to
/// (MAPPS-1099). The string form is what the `invoices.external_provider`
/// column stores and what `integrations.provider` carries, so the two
/// join on a plain equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvoiceProviderKind {
    Xero,
    Quickbooks,
}

impl InvoiceProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xero => "xero",
            Self::Quickbooks => "quickbooks",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "xero" => Some(Self::Xero),
            "quickbooks" => Some(Self::Quickbooks),
            _ => None,
        }
    }
}

/// What an external provider gave back after issuing an invoice on behalf
/// of a tenant. Phase 1 defines the shape; Phase 1b / 1c clients will
/// return one of these from their `issue_invoice` implementations, and
/// Phase 2's dispatch will store it on the local row (as
/// `external_provider`, `external_invoice_id` and `external_number`
/// together). Kept here rather than inside the eventual provider
/// modules so the schema stays the single source of truth and the two
/// clients speak one shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalInvoiceRef {
    pub provider: InvoiceProviderKind,
    pub external_invoice_id: String,
    pub external_number: String,
}

/// What a provider gave back after issuing a credit note (PMS-1546).
///
/// Three fields like [`ExternalInvoiceRef`] rather than the bill's one,
/// and for the same reason that one has three: a credit note is a
/// document the CUSTOMER is given, so the number the provider rendered is
/// what they will quote back and what reconciliation matches on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalCreditNoteRef {
    pub provider: InvoiceProviderKind,
    pub external_credit_note_id: String,
    pub external_number: String,
}

/// What a provider gave back for a bill it now holds (MAPPS-1155).
///
/// One field and not three, which is the difference from
/// [`ExternalInvoiceRef`]: a bill carries no number the MSP has to show
/// anybody. The invoice number matters because a customer reads it off a
/// document; a bill's number is the VENDOR's, it is already on the paper
/// the MSP received, and it lives in `bills.bill_number` whether or not
/// the bill is delegated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalBillRef {
    pub provider: InvoiceProviderKind,
    pub external_bill_id: String,
}

/// What a provider says has been settled against one document
/// (PMS-1543).
///
/// Minor units, like every amount in the bills subsystem. Carried as the
/// provider's RUNNING TOTAL rather than as one payment, because a webhook
/// says "this changed" and not "this much arrived": reading the total and
/// recording the difference makes a redelivery a no-op by arithmetic
/// instead of by a dedupe table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalSettlement {
    pub paid_minor: i64,
    pub total_minor: i64,
    pub voided: bool,
}

/// A provider's decimal amount (`"120.50"`, or a JSON number rendered as
/// one) in minor units, truncating rather than rounding.
///
/// Truncation is deliberate and matches `BillTotals::from_lines`: a
/// third decimal from a provider is a precision Mokosh's columns do not
/// hold, and rounding it up would record a payment larger than the one
/// that was made.
pub fn decimal_string_to_minor(raw: &str) -> i64 {
    let trimmed = raw.trim();
    let (sign, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, trimmed),
    };
    let (whole, frac) = digits.split_once('.').unwrap_or((digits, ""));
    let whole: i64 = whole.parse().unwrap_or(0);
    let mut cents = 0i64;
    for (i, c) in frac.chars().take(2).enumerate() {
        let d = c.to_digit(10).unwrap_or(0) as i64;
        cents += if i == 0 { d * 10 } else { d };
    }
    sign * (whole.saturating_mul(100).saturating_add(cents))
}

/// What a provider calls the reimbursement it now holds (PMS-1541).
///
/// A Xero `BankTransactionID` or a QuickBooks `Purchase.Id`. Its own type
/// rather than a reuse of [`ExternalBillRef`]: a bill and a reimbursement
/// are different documents over there, and a column named for one holding
/// the id of the other is how a reconciliation reads the wrong ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalExpenseRef {
    pub provider: InvoiceProviderKind,
    pub external_expense_id: String,
}

/// MAPPS-1099 Phase 2: what the dispatch decided to do with a given
/// `create_invoice` call, before any wire I/O. Local means the current
/// Mokosh path (number allocation + row insert + mail dispatch);
/// `Delegated` names an external provider the invoice should be issued
/// through. Phase 2b wires it into `BillingService::create_invoice`
/// behind the same feature flag the Phase 2 dispatch helper reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerSelection {
    Local,
    Delegated { provider: InvoiceProviderKind },
}

/// Phase 2 dispatch helper. Pure logic over the two inputs it reads:
/// the deployment-wide feature toggle (gates the whole delegated path,
/// so the merge is a no-op on every environment until operations flips
/// it on in staging), and the tenant's `integrations` row for Xero or
/// QuickBooks (names the delegation, when the capability is enabled).
///
/// The signature takes the two capability predicates as closures so a
/// unit test exercises every branch without a running `IntegrationsService`
/// or a seeded Postgres. The real caller passes a lambda that reads
/// `IntegrationsService::get(tenant, provider).enabled_capabilities`
/// and checks for `Capability::Invoicing`.
pub fn select_issuer_with(
    flag_on: bool,
    xero_delegated: impl FnOnce() -> bool,
    quickbooks_delegated: impl FnOnce() -> bool,
) -> IssuerSelection {
    if !flag_on {
        return IssuerSelection::Local;
    }
    // Xero before QuickBooks is a stable tie-break (a tenant with both
    // integrations connected is improbable, but the decision has to be
    // deterministic so a user does not see one provider sometimes and
    // the other another time). Reorder once product has a rule for the
    // double-connected case.
    if xero_delegated() {
        return IssuerSelection::Delegated {
            provider: InvoiceProviderKind::Xero,
        };
    }
    if quickbooks_delegated() {
        return IssuerSelection::Delegated {
            provider: InvoiceProviderKind::Quickbooks,
        };
    }
    IssuerSelection::Local
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoice_provider_kind_round_trips_through_parse() {
        for kind in [InvoiceProviderKind::Xero, InvoiceProviderKind::Quickbooks] {
            assert_eq!(InvoiceProviderKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(InvoiceProviderKind::parse("stripe"), None);
        assert_eq!(InvoiceProviderKind::parse(""), None);
    }

    /// Pin the stored string set in the shape migration 278's doc comment
    /// names ("xero or quickbooks"), so a future enum variant forces a
    /// deliberate schema update rather than drifting the two apart.
    #[test]
    fn provider_strings_match_the_migration_doc_comment() {
        const MIGRATION: &str =
            include_str!("../../../migrations/278_invoices_external_issuer.sql");
        for name in ["xero", "quickbooks"] {
            assert!(
                MIGRATION.contains(name),
                "provider name {name:?} is not in migration 278's doc comment"
            );
        }
    }

    /// MAPPS-1099: the flag off is a hard veto. Even a tenant with both
    /// providers connected and both carrying `Capability::Invoicing`
    /// stays on the local path, so a merge that turns no flag on is a
    /// no-op on every environment.
    #[test]
    fn flag_off_pins_every_tenant_to_the_local_path() {
        assert_eq!(
            select_issuer_with(false, || true, || true),
            IssuerSelection::Local
        );
    }

    /// Flag on, nothing delegated: still local. The dispatch only fires
    /// when a tenant actively picked a provider.
    #[test]
    fn flag_on_without_a_delegation_stays_local() {
        assert_eq!(
            select_issuer_with(true, || false, || false),
            IssuerSelection::Local
        );
    }

    #[test]
    fn flag_on_with_xero_delegated_picks_xero() {
        assert_eq!(
            select_issuer_with(true, || true, || false),
            IssuerSelection::Delegated {
                provider: InvoiceProviderKind::Xero
            }
        );
    }

    #[test]
    fn flag_on_with_quickbooks_delegated_picks_quickbooks() {
        assert_eq!(
            select_issuer_with(true, || false, || true),
            IssuerSelection::Delegated {
                provider: InvoiceProviderKind::Quickbooks
            }
        );
    }

    /// With both connected, Xero wins deterministically. A later product
    /// rule can reorder; the invariant that pins HERE is that the result
    /// never alternates between calls for the same tenant.
    #[test]
    fn with_both_delegated_the_tie_break_is_xero_first() {
        assert_eq!(
            select_issuer_with(true, || true, || true),
            IssuerSelection::Delegated {
                provider: InvoiceProviderKind::Xero
            }
        );
    }

    /// PMS-1543: a provider's decimal amount in minor units, truncating.
    ///
    /// Truncation matches `BillTotals::from_lines`, and the direction
    /// matters: rounding a third decimal UP would record a payment larger
    /// than the one the provider made.
    #[test]
    fn a_provider_amount_becomes_minor_units() {
        assert_eq!(decimal_string_to_minor("70"), 7000);
        assert_eq!(decimal_string_to_minor("70.00"), 7000);
        assert_eq!(
            decimal_string_to_minor("70.5"),
            7050,
            "one decimal is tenths"
        );
        assert_eq!(decimal_string_to_minor(" 1234.56 "), 123456);
        assert_eq!(
            decimal_string_to_minor("70.999"),
            7099,
            "a third decimal is dropped, never rounded up"
        );
        assert_eq!(decimal_string_to_minor("-5.00"), -500);
        assert_eq!(
            decimal_string_to_minor("not a number"),
            0,
            "an unreadable amount is nothing rather than a panic: the caller is a webhook"
        );
    }
}
