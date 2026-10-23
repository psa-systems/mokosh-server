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
}
