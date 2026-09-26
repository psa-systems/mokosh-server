//! Integration vocabulary: the capabilities an integration can provide, the
//! providers that can provide them, and the states an installation is in.
//!
//! Here rather than server-side because the admin integrations page renders a
//! checkbox per capability and a badge per status, and the alternative is the
//! client holding them as `String` and re-deriving the labels, which is the
//! drift PMS-1375 took out of billing: nothing fails to compile when the
//! server's vocabulary moves.
//!
//! What is deliberately NOT here is which capabilities a given provider
//! SUPPORTS. That is a property of the provider's implementation in a
//! particular server build, not of the wire format, so it lives in
//! `mokosh_server::modules::integrations::registry` and is served to the
//! client rather than compiled into it. A client that shipped its own copy
//! would offer a tenant a capability the server would refuse.

// These model enums expose `from_str(&str) -> Option<Self>` as a deliberate
// infallible-style parser API; they intentionally do not implement
// `std::str::FromStr` (which requires a `Result`).
#![allow(clippy::should_implement_trait)]

use serde::{Deserialize, Serialize};

/// What an integration is allowed to do for a tenant.
///
/// A capability answers the question connecting a provider does not: who owns
/// the work. Saying Stripe is connected says nothing about whether Stripe,
/// Mokosh or Xero issues the invoice, so a tenant delegates capabilities one at
/// a time and an integration declares which ones it can accept.
///
/// These are the categories named in the standup PMS-1310 came out of. EXTEND
/// this list rather than renaming a variant: the string form is stored in
/// `integrations.enabled_capabilities`, so a rename is a data migration and a
/// silently-dropped delegation for any row that still holds the old spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Taking money: the provider hosts the payment and tells Mokosh it
    /// happened.
    Payments,
    /// Issuing the document the customer receives.
    Invoicing,
    /// Selling at a counter, where the provider owns the terminal.
    PointOfSale,
    /// What the MSP itself is billed for, and what it spends.
    BillsAndExpenses,
    /// People and organisations, synchronised both ways or one.
    Contacts,
}

impl Capability {
    /// Every capability, in a stable order so a served catalog and a rendered
    /// checkbox list agree without either sorting.
    pub const ALL: &'static [Capability] = &[
        Capability::Payments,
        Capability::Invoicing,
        Capability::PointOfSale,
        Capability::BillsAndExpenses,
        Capability::Contacts,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Payments => "payments",
            Self::Invoicing => "invoicing",
            Self::PointOfSale => "point_of_sale",
            Self::BillsAndExpenses => "bills_and_expenses",
            Self::Contacts => "contacts",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "payments" => Some(Self::Payments),
            "invoicing" => Some(Self::Invoicing),
            "point_of_sale" => Some(Self::PointOfSale),
            "bills_and_expenses" => Some(Self::BillsAndExpenses),
            "contacts" => Some(Self::Contacts),
            _ => None,
        }
    }

    /// The checkbox label. Held beside the key so one edit moves both, the
    /// `portal_roles::capability_labels` arrangement.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Payments => "Payments",
            Self::Invoicing => "Invoicing",
            Self::PointOfSale => "Point of sale",
            Self::BillsAndExpenses => "Bills and expenses",
            Self::Contacts => "Contacts",
        }
    }

    /// The one sentence under the checkbox, which has to say what handing this
    /// over MEANS rather than restate the label.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Payments => {
                "The provider collects the money. Invoices carry a pay-now link to its \
                 hosted page and the payment is recorded here when it reports one."
            }
            Self::Invoicing => {
                "The provider issues the document the customer receives. Mokosh stops \
                 being the system of record for invoice numbering and delivery."
            }
            Self::PointOfSale => {
                "The provider owns the counter terminal. Sales made there arrive here as \
                 completed transactions."
            }
            Self::BillsAndExpenses => {
                "The provider holds what the MSP is billed for and what it spends, so \
                 costs are reconciled there rather than entered here."
            }
            Self::Contacts => {
                "People and organisations are synchronised with the provider's directory \
                 instead of being maintained only here."
            }
        }
    }
}

/// A provider an integration can be installed for.
///
/// The string form is stored in `integrations.provider` and CHECKed there, so
/// the two lists move together: adding a variant means a migration that widens
/// the CHECK and a registry entry that declares what it supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationProvider {
    Stripe,
    Paypal,
    Quickbooks,
    Xero,
    Google,
    Microsoft,
}

impl IntegrationProvider {
    pub const ALL: &'static [IntegrationProvider] = &[
        IntegrationProvider::Stripe,
        IntegrationProvider::Paypal,
        IntegrationProvider::Quickbooks,
        IntegrationProvider::Xero,
        IntegrationProvider::Google,
        IntegrationProvider::Microsoft,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stripe => "stripe",
            Self::Paypal => "paypal",
            Self::Quickbooks => "quickbooks",
            Self::Xero => "xero",
            Self::Google => "google",
            Self::Microsoft => "microsoft",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "stripe" => Some(Self::Stripe),
            "paypal" => Some(Self::Paypal),
            "quickbooks" => Some(Self::Quickbooks),
            "xero" => Some(Self::Xero),
            "google" => Some(Self::Google),
            "microsoft" => Some(Self::Microsoft),
            _ => None,
        }
    }
}

/// Where an installation stands; mirrors the CHECK on `integrations.status`.
///
/// `Disconnected` is not a flavour of `NotConnected`, for the reason
/// `contact_sync_connections.sync_status` separates `throttled` from `failed`:
/// an integration a tenant switched off is not one they never set up, and the
/// capability set it was trusted with is worth keeping so reconnecting does not
/// start from an empty page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationStatus {
    NotConnected,
    Connected,
    Error,
    Disconnected,
}

impl IntegrationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotConnected => "not_connected",
            Self::Connected => "connected",
            Self::Error => "error",
            Self::Disconnected => "disconnected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "not_connected" => Some(Self::NotConnected),
            "connected" => Some(Self::Connected),
            "error" => Some(Self::Error),
            "disconnected" => Some(Self::Disconnected),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant round-trips through its stored spelling. This is what
    /// stops a rename from reading as a dropped delegation: an
    /// `enabled_capabilities` entry that no longer parses is a capability the
    /// tenant chose and the server silently ignores.
    #[test]
    fn every_capability_and_provider_round_trips_its_stored_spelling() {
        for capability in Capability::ALL {
            assert_eq!(
                Capability::from_str(capability.as_str()),
                Some(*capability),
                "{} does not parse back",
                capability.as_str()
            );
        }
        for provider in IntegrationProvider::ALL {
            assert_eq!(
                IntegrationProvider::from_str(provider.as_str()),
                Some(*provider),
                "{} does not parse back",
                provider.as_str()
            );
        }
        for status in [
            IntegrationStatus::NotConnected,
            IntegrationStatus::Connected,
            IntegrationStatus::Error,
            IntegrationStatus::Disconnected,
        ] {
            assert_eq!(IntegrationStatus::from_str(status.as_str()), Some(status));
        }
    }

    /// `ALL` is the list the catalog is built from, so a variant missing from
    /// it is a capability no tenant can ever be offered.
    #[test]
    fn the_all_lists_hold_every_variant() {
        assert_eq!(
            Capability::ALL.len(),
            5,
            "a capability was added without adding it to Capability::ALL"
        );
        assert_eq!(
            IntegrationProvider::ALL.len(),
            6,
            "a provider was added without adding it to IntegrationProvider::ALL"
        );
    }
}
