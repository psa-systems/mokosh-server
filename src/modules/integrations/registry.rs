//! PMS-1310: what each provider can do, and who owns its connection today.
//!
//! The registry is the answer to "who does the invoicing". A tenant delegates
//! capabilities one at a time, and it may only delegate what the provider's
//! implementation in THIS build can accept, so the supported set is declared
//! here in code rather than stored on the row: a column could hold a
//! capability the code cannot serve, and nothing would fail until a tenant
//! relied on it.
//!
//! # One home per connection
//!
//! Three per-tenant connection tables predate this subsystem, and two of them
//! already answer whether a provider in this list is connected:
//! `payment_gateway_configs` for Stripe and PayPal, `contact_sync_connections`
//! for Google. If the `integrations` table also answered that while they do,
//! there would be two homes for one fact and the only certainty is that they
//! would eventually disagree.
//!
//! So each entry names the subsystem that owns its connection, and
//! [`IntegrationsService`](super::service::IntegrationsService) refuses
//! `connect`, `disconnect` and a capability change for a provider whose home is
//! still elsewhere, naming where it is configured and the issue that moves it.
//! No `integrations` row exists for such a provider at all, so the two tables
//! cannot diverge in the meantime. PMS-1312 (Stripe) and PMS-1315 (contacts)
//! each flip one entry to [`ConnectionHome::Integrations`] and backfill its
//! rows in the same change.
//!
//! `rmm_connections` is deliberately absent: RMM is not one of the capabilities
//! this subsystem arbitrates, so folding it in would widen the concept to mean
//! "every third party" rather than "who owns a piece of the money and contact
//! workflow".

use mokosh_types::integrations::{Capability, IntegrationProvider};

/// Which subsystem owns whether a provider is connected for a tenant.
///
/// Not a boolean, because the useful thing to say to an operator staring at the
/// integrations page is WHERE to go instead, and the useful thing to say to the
/// next reader is which issue moves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHome {
    /// The `integrations` table. `connect` and `disconnect` here do the work.
    Integrations,
    /// Another table, with its own settings surface. `table` is the table, and
    /// `issue` is the issue that brings it under this subsystem.
    Elsewhere {
        table: &'static str,
        configured_at: &'static str,
        issue: &'static str,
    },
}

/// How often a provider is polled, for one that is polled at all.
///
/// PMS-1310 set the default at fifteen minutes and said to revise it if
/// validation shows otherwise, so it is one number in one place rather than a
/// literal at each call site. The floor matches
/// `integrations.poll_interval_minutes`'s CHECK and
/// `contact_sync_connections.sync_interval_minutes`: a one-minute poll against
/// a third party is a rate limit waiting to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollingSpec {
    pub default_minutes: i32,
    pub min_minutes: i32,
}

/// The default poll interval PMS-1310 settled on.
pub const DEFAULT_POLL_INTERVAL_MINUTES: i32 = 15;
/// The floor, mirroring the CHECK on `integrations.poll_interval_minutes`.
pub const MIN_POLL_INTERVAL_MINUTES: i32 = 5;

const POLLED: PollingSpec = PollingSpec {
    default_minutes: DEFAULT_POLL_INTERVAL_MINUTES,
    min_minutes: MIN_POLL_INTERVAL_MINUTES,
};

/// Everything the integrations page needs about one provider, and everything
/// the service needs to refuse a request it should refuse.
#[derive(Debug, Clone, Copy)]
pub struct ProviderDescriptor {
    pub provider: IntegrationProvider,
    /// How the provider names itself, which is what an operator looks for.
    pub display_name: &'static str,
    /// What installing it does, in the terms of the capabilities below. This is
    /// the "each entry describes what it does" half of the reference page
    /// PMS-1310 was written against.
    pub description: &'static str,
    /// What this build can actually hand to the provider.
    /// `enabled_capabilities` must be a subset of it.
    pub supported_capabilities: &'static [Capability],
    /// `None` for a provider nothing polls, so no poll setting is offered.
    pub polling: Option<PollingSpec>,
    pub connection_home: ConnectionHome,
}

impl ProviderDescriptor {
    pub fn supports(&self, capability: Capability) -> bool {
        self.supported_capabilities.contains(&capability)
    }
}

/// Every provider, in the order the integrations page lists them.
///
/// The `provider` strings are the same set the CHECK on
/// `integrations.provider` accepts (migration 251); adding one means widening
/// that CHECK in a new migration and adding a variant to
/// [`IntegrationProvider`] in the same change.
pub const REGISTRY: &[ProviderDescriptor] = &[
    ProviderDescriptor {
        provider: IntegrationProvider::Stripe,
        display_name: "Stripe",
        description: "Collect card payments on a hosted page, with a pay-now link on every \
                      invoice. Stripe can also issue invoices of its own; take `payments` \
                      alone to keep Mokosh as the system of record for the document.",
        supported_capabilities: &[
            Capability::Payments,
            Capability::Invoicing,
            Capability::PointOfSale,
        ],
        polling: None,
        connection_home: ConnectionHome::Elsewhere {
            table: "payment_gateway_configs",
            configured_at: "Settings > Payment gateways",
            issue: "PMS-1312",
        },
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Paypal,
        display_name: "PayPal",
        description: "Collect payments through PayPal checkout. PayPal does not charge on \
                      approval, so a payment is recorded when the capture completes.",
        supported_capabilities: &[Capability::Payments],
        polling: None,
        connection_home: ConnectionHome::Elsewhere {
            table: "payment_gateway_configs",
            configured_at: "Settings > Payment gateways",
            issue: "PMS-1312",
        },
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Quickbooks,
        display_name: "QuickBooks",
        description: "Hand the accounting over: QuickBooks issues the invoice the customer \
                      receives and holds what the MSP is billed for.",
        supported_capabilities: &[Capability::Invoicing, Capability::BillsAndExpenses],
        polling: Some(POLLED),
        connection_home: ConnectionHome::Integrations,
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Xero,
        display_name: "Xero",
        description: "Hand the accounting over: Xero issues the invoice the customer \
                      receives and holds what the MSP is billed for.",
        supported_capabilities: &[Capability::Invoicing, Capability::BillsAndExpenses],
        polling: Some(POLLED),
        connection_home: ConnectionHome::Integrations,
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Google,
        display_name: "Google",
        description: "Synchronise people and organisations with Google Contacts, so a \
                      directory the MSP already maintains is not maintained twice.",
        supported_capabilities: &[Capability::Contacts],
        polling: Some(POLLED),
        connection_home: ConnectionHome::Elsewhere {
            table: "contact_sync_connections",
            configured_at: "Settings > Contact sync",
            issue: "PMS-1315",
        },
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Microsoft,
        display_name: "Microsoft 365",
        description: "Synchronise people and organisations with Microsoft 365 contacts, \
                      the same bargain as Google against the directory most MSP customers \
                      are already on.",
        supported_capabilities: &[Capability::Contacts],
        polling: Some(POLLED),
        connection_home: ConnectionHome::Integrations,
    },
];

/// The descriptor for `provider`. Infallible by construction: every
/// [`IntegrationProvider`] variant has an entry, and
/// [`tests::every_provider_variant_has_exactly_one_registry_entry`] is what
/// keeps that true.
pub fn descriptor(provider: IntegrationProvider) -> &'static ProviderDescriptor {
    REGISTRY
        .iter()
        .find(|entry| entry.provider == provider)
        .expect("every IntegrationProvider variant has a registry entry")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is read through [`descriptor`], which expects an entry, so
    /// a variant added without one is a panic on the first request naming it.
    /// Exactly one, because two entries would make the supported set depend on
    /// iteration order.
    #[test]
    fn every_provider_variant_has_exactly_one_registry_entry() {
        for provider in IntegrationProvider::ALL {
            let matches = REGISTRY
                .iter()
                .filter(|entry| entry.provider == *provider)
                .count();
            assert_eq!(
                matches,
                1,
                "{} has {matches} registry entries, want exactly 1",
                provider.as_str()
            );
        }
        assert_eq!(
            REGISTRY.len(),
            IntegrationProvider::ALL.len(),
            "the registry holds an entry for a provider that is not an IntegrationProvider"
        );
    }

    /// A provider that supports nothing can be installed and then does nothing,
    /// which is a row an operator cannot act on and a page entry that cannot be
    /// explained.
    #[test]
    fn every_provider_supports_at_least_one_capability() {
        for entry in REGISTRY {
            assert!(
                !entry.supported_capabilities.is_empty(),
                "{} supports no capability",
                entry.provider.as_str()
            );
        }
    }

    /// Duplicates in the supported set would make the subset check pass for a
    /// reason nobody intended and the checkbox list render the same row twice.
    #[test]
    fn no_provider_lists_a_capability_twice() {
        for entry in REGISTRY {
            let mut seen: Vec<Capability> = entry.supported_capabilities.to_vec();
            seen.sort();
            let before = seen.len();
            seen.dedup();
            assert_eq!(
                seen.len(),
                before,
                "{} lists a capability more than once",
                entry.provider.as_str()
            );
        }
    }

    /// The poll floor the registry hands out has to be the floor the database
    /// enforces, or a value the service accepts is a constraint violation.
    #[test]
    fn the_polling_floor_matches_the_column_check() {
        for entry in REGISTRY {
            let Some(polling) = entry.polling else {
                continue;
            };
            assert_eq!(
                polling.min_minutes,
                MIN_POLL_INTERVAL_MINUTES,
                "{} has a floor the CHECK on integrations.poll_interval_minutes does not",
                entry.provider.as_str()
            );
            assert!(
                polling.default_minutes >= polling.min_minutes,
                "{} defaults below its own floor",
                entry.provider.as_str()
            );
        }
    }

    /// Every capability in the shared vocabulary is offered by somebody. A
    /// capability nothing supports is one a tenant can never delegate, which
    /// means the enum promises something the build does not do.
    #[test]
    fn every_capability_is_supported_by_at_least_one_provider() {
        for capability in Capability::ALL {
            assert!(
                REGISTRY.iter().any(|entry| entry.supports(*capability)),
                "no provider supports {}",
                capability.as_str()
            );
        }
    }
}
