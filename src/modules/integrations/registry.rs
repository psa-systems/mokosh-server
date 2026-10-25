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
//! also answered whether a provider in this list is connected:
//! `payment_gateway_configs` for Stripe and PayPal, `contact_sync_connections`
//! for Google. If the `integrations` table answered that as well, there would be
//! two homes for one fact and the only certainty is that they would eventually
//! disagree.
//!
//! So each entry names the subsystem that owns its connection, and
//! [`IntegrationsService`](super::service::IntegrationsService) refuses
//! `connect`, `disconnect` and a capability change for a provider whose home is
//! still elsewhere, naming where it is configured and the issue that moves it.
//! No `integrations` row exists for such a provider at all, so the two tables
//! cannot diverge in the meantime. PMS-1315 flips the remaining entry (Google)
//! and backfills its rows in the same change.
//!
//! PMS-1312 did that for Stripe and PayPal: `integrations.status` is now the
//! home of whether a payment provider is connected for a tenant, migration 256
//! backfilled a row per gateway, and `payment_gateway_configs.is_active` is a
//! one-way mirror written by one function and read by nothing (see
//! [`super::connection`]).
//!
//! # A connection home is not a credential home
//!
//! Those two came apart in the same change, which is why
//! [`CredentialHome`] exists beside [`ConnectionHome`]. Stripe cannot be
//! connected by pressing a button: it needs a secret key and a webhook signing
//! secret, per-provider settings beside them (`is_test_mode`,
//! `client_display_name`, `min_partial_amount`), and a validation pass that
//! parses the blob into that provider's own shape. That surface is
//! `PUT /api/v1/payment-gateways`, it already exists, and reproducing it
//! here would be a second place to enter one credential. So the credential stays
//! addressed as `SecretKind::PaymentGateway` and entered there, while the
//! connected fact lives here.
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

/// Which secret address holds an installation's credential, and therefore which
/// surface the operator enters it on.
///
/// Separate from [`ConnectionHome`] because PMS-1312 separated them: a payment
/// provider's connected fact moved into `integrations` while its credential
/// stayed where the payments surface already writes it. Collapsing the two into
/// one flag would make the next payment provider either grow a second credential
/// form or lose its per-provider settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialHome {
    /// `SecretKind::Integration`, written by
    /// [`IntegrationsService::connect`](super::service::IntegrationsService::connect)
    /// and deleted by `disconnect`. The credential arrives in the connect
    /// request, so connecting is one act.
    Integration,
    /// `SecretKind::PaymentGateway`, written by
    /// `PUT /api/v1/payment-gateways` and deleted by its DELETE.
    ///
    /// `connect` here therefore takes NO credential and refuses one that is
    /// sent, because a credential written to the other address would be a secret
    /// nothing reads; it also refuses when none is stored yet, since a
    /// `connected` row with no credential is the state this subsystem exists to
    /// prevent. `disconnect` leaves the stored credential alone, so an MSP who
    /// switches payments off for a month does not have to find their keys again;
    /// the gateway DELETE is what removes it.
    PaymentGateway,
    /// `SecretKind::ContactSync`, written by the contact-sync OAuth flow.
    ///
    /// Read by nothing today: the only provider carrying it is Google, whose
    /// connection home is still [`ConnectionHome::Elsewhere`], so `connect` here
    /// is refused before the credential home is consulted. It is stated rather
    /// than left as `Integration` because that key is keyed by the CONNECTION id
    /// as well as the provider (a reconnect must not resolve the old token), so
    /// PMS-1315 has one more question to answer than PMS-1312 did and the
    /// difference belongs in the registry rather than in whoever reads it next.
    ContactSync,
    /// `SecretKind::Integration`, written by the invoice-issuer OAuth round
    /// trip on the provider's own settings page (MAPPS-1142).
    ///
    /// The same storage as [`Self::Integration`] and a different home,
    /// because what matters here is not where the bytes live but whether
    /// this surface can produce them. Nothing is ENTERED: it is a consent
    /// round trip, so there is no field to render and no credential for a
    /// Connect button on Connected Services to send. That is why
    /// `entered_at` answers `None` and [`ProviderDescriptor::setup_surface`]
    /// names the page instead, per provider - Xero and QuickBooks have
    /// different ones, which is the same reason MAPPS-1122 made the surface
    /// per provider rather than per credential home.
    InvoiceIssuer,
}

impl CredentialHome {
    /// The key a client switches on, matching the `snake_case` the rest of this
    /// surface serialises enums with.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integration => "integration",
            Self::PaymentGateway => "payment_gateway",
            Self::ContactSync => "contact_sync",
            Self::InvoiceIssuer => "invoice_issuer",
        }
    }

    /// The settings surface an operator enters the credential on, or `None`
    /// when it arrives in the connect request.
    ///
    /// On the home rather than on each descriptor, because it IS a property of
    /// the home: two payment providers do not get to disagree about where the
    /// payments surface is. The strings match the SPA's own page titles, since
    /// their only job is to be read by somebody looking for that screen
    /// (PMS-1447).
    pub fn entered_at(self) -> Option<&'static str> {
        match self {
            // The credential arrives with the connect request, so there is no
            // other surface to name.
            Self::Integration => None,
            Self::PaymentGateway => Some("Settings > Payment Gateways"),
            Self::ContactSync => Some("Settings > Google Contacts"),
            // Nothing is entered: the credential is an OAuth grant, so
            // there is no surface where somebody types one. Which page
            // STARTS that grant differs per provider and is
            // `setup_surface`'s answer, not this one's.
            Self::InvoiceIssuer => None,
        }
    }
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

/// Whether there is anything behind a registry entry (MAPPS-1121).
///
/// PMS-1310 built the capability model before the providers, which is a
/// reasonable order to build in and left a gap nothing stated: a provider is
/// listed here whether or not a line of code can act on it. The page therefore
/// offered QuickBooks, Xero and Microsoft 365 a credential field, and
/// `connect` stored whatever was typed into it and answered `connected`. Both
/// ends were honest on their own terms and the result was a tenant told that a
/// delegation had happened when nothing could act on it.
///
/// So the entry now says. `Planned` is not a lesser entry: the capability
/// vocabulary is the point of the registry, and a provider nobody can see is a
/// provider nobody can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderBuild {
    /// A client exists and something acts on the capabilities.
    Built,
    /// Declared so the capability model can name it; nothing behind it yet.
    ///
    /// `tracked_by` is the issue that builds it, kept here rather than in the
    /// client so the two cannot disagree, and NOT rendered to a tenant: an MSP
    /// reading their own settings has no use for our issue keys.
    Planned { tracked_by: &'static str },
}

impl ProviderBuild {
    pub fn is_built(self) -> bool {
        matches!(self, ProviderBuild::Built)
    }
}

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
    pub credential_home: CredentialHome,
    /// Whether this build can actually do anything with the provider
    /// (MAPPS-1121).
    pub build: ProviderBuild,
}

impl ProviderDescriptor {
    pub fn supports(&self, capability: Capability) -> bool {
        self.supported_capabilities.contains(&capability)
    }

    /// Whether this provider's lifecycle can be CHANGED through the
    /// integrations HTTP surface.
    ///
    /// A payment provider's credential, test/live mode and active toggle live
    /// entirely on `Settings > Payment Gateways`, and a second connect button
    /// here on top of that is the redundancy MAPPS-1098 removed, so the four
    /// per-provider routes still refuse it.
    ///
    /// MAPPS-1122 split this from being LISTED. MAPPS-1098 used one predicate
    /// for both and dropped the payment providers out of `GET /integrations`
    /// as well, which left the page unable to answer the question it exists
    /// for: an operator looking at "what is this organization connected to"
    /// got a list with the two providers most organizations actually use
    /// missing from it. Listing a provider costs nothing and says something;
    /// offering a second place to change it was the problem.
    pub fn is_writable_on_integrations_page(&self) -> bool {
        // A whitelist since MAPPS-1153, and the inversion is the point. It
        // used to answer "anything that is not a payment gateway", so a
        // credential home added later became writable here by default and
        // nobody had to decide that. `Integration` is the only home whose
        // credential arrives in the connect request, which is the only way
        // this surface can connect anything.
        matches!(self.credential_home, CredentialHome::Integration)
    }

    /// The settings surface that owns this provider's setup, for the panel's
    /// one action (MAPPS-1122).
    ///
    /// Served rather than derived from the provider name by the client, the
    /// reason `credential_elsewhere` is served (PMS-1447): the client cannot
    /// know that Google's credential page and iCloud's are different pages,
    /// and `CredentialHome::ContactSync` alone cannot say so because it names
    /// one surface for three providers.
    ///
    /// `None` for a provider that has no setup surface yet, which is the two
    /// planned ones: there is nowhere to send an operator until their clients
    /// exist (MAPPS-1121).
    pub fn setup_surface(&self) -> Option<SetupSurface> {
        match (self.provider, self.credential_home) {
            (_, CredentialHome::PaymentGateway) => Some(SetupSurface {
                kind: "payment_gateway",
                label: "Settings > Payment Gateways",
            }),
            (IntegrationProvider::Google, _) => Some(SetupSurface {
                kind: "contact_sync_google",
                label: "Settings > Google Contacts",
            }),
            (IntegrationProvider::Icloud, _) => Some(SetupSurface {
                kind: "contact_sync_icloud",
                label: "Settings > iCloud Contacts",
            }),
            (IntegrationProvider::Microsoft, _) => Some(SetupSurface {
                kind: "contact_sync_microsoft",
                label: "Settings > Microsoft 365 Contacts",
            }),
            // MAPPS-1153: each issuer has its own page, which is where the
            // consent round trip starts and where the mappings live.
            (IntegrationProvider::Xero, _) => Some(SetupSurface {
                kind: "invoice_issuer_xero",
                label: "Settings > Xero",
            }),
            (IntegrationProvider::Quickbooks, _) => Some(SetupSurface {
                kind: "invoice_issuer_quickbooks",
                label: "Settings > QuickBooks",
            }),
            _ => None,
        }
    }
}

/// Where a provider is set up, as the panel renders it (MAPPS-1122).
///
/// `kind` is the contract the client routes on; `label` is the prose a reader
/// sees. Two fields because the string an operator reads has already changed
/// once and a client that routed on it would have broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupSurface {
    pub kind: &'static str,
    pub label: &'static str,
}

/// Every provider, in the order the integrations page lists them.
///
/// The `provider` strings are the same set the CHECK on
/// `integrations.provider` accepts (migration 252); adding one means widening
/// that CHECK in a new migration and adding a variant to
/// [`IntegrationProvider`] in the same change.
pub const REGISTRY: &[ProviderDescriptor] = &[
    ProviderDescriptor {
        provider: IntegrationProvider::Stripe,
        display_name: "Stripe",
        description: "Collect card payments on a hosted page, with a pay-now link on every \
                      invoice. Mokosh stays the system of record for the document.",
        // PMS-1525: `Invoicing` was declared here and no issuer could receive
        // it. `ExternalInvoicingProvider` has two variants, Xero and
        // QuickBooks, `invoice_issuer_dispatch` reads the capability for those
        // two and for nothing else, and `issuer_delegation`'s own comment says
        // Stripe is never an invoicing provider because its invoicing is
        // "pay-now links on Mokosh-issued invoices", which is what
        // `Capability::Payments` already means. A declared capability nothing
        // can act on is a promise to an operator, and the rows carrying it were
        // a delegation waiting to switch itself on the day somebody shipped a
        // Stripe issuer. It comes back with that client, as PayPal's entry
        // shows a payment provider looks without it.
        supported_capabilities: &[Capability::Payments],
        polling: None,
        connection_home: ConnectionHome::Integrations,
        credential_home: CredentialHome::PaymentGateway,
        build: ProviderBuild::Built,
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Paypal,
        display_name: "PayPal",
        description: "Collect payments through PayPal checkout. PayPal does not charge on \
                      approval, so a payment is recorded when the capture completes.",
        supported_capabilities: &[Capability::Payments],
        polling: None,
        connection_home: ConnectionHome::Integrations,
        credential_home: CredentialHome::PaymentGateway,
        build: ProviderBuild::Built,
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Quickbooks,
        display_name: "QuickBooks",
        description: "Hand the accounting over: QuickBooks issues the invoice the customer \
                      receives and holds what the MSP is billed for.",
        supported_capabilities: &[Capability::Invoicing, Capability::BillsAndExpenses],
        polling: Some(POLLED),
        connection_home: ConnectionHome::Integrations,
        credential_home: CredentialHome::InvoiceIssuer,
        build: ProviderBuild::Built,
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Xero,
        display_name: "Xero",
        description: "Hand the accounting over: Xero issues the invoice the customer \
                      receives and holds what the MSP is billed for.",
        supported_capabilities: &[Capability::Invoicing, Capability::BillsAndExpenses],
        polling: Some(POLLED),
        connection_home: ConnectionHome::Integrations,
        credential_home: CredentialHome::InvoiceIssuer,
        build: ProviderBuild::Built,
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
        credential_home: CredentialHome::ContactSync,
        build: ProviderBuild::Built,
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Microsoft,
        display_name: "Microsoft 365",
        description: "Synchronise people and organisations with Microsoft 365 contacts, \
                      the same bargain as Google against the directory most MSP customers \
                      are already on.",
        supported_capabilities: &[Capability::Contacts],
        polling: Some(POLLED),
        // MAPPS-1121: this entry said the connection was made here, with a
        // credential pasted into the integrations page. MAPPS-1101 shipped the
        // real thing and it is the Entra consent round trip in `contact_sync`:
        // `POST /integrations/contact-sync/microsoft/authorize` writes
        // `contact_sync_connections`, exactly as Google does. So the entry now
        // says what Google's has always said, and this surface refuses to
        // connect it.
        connection_home: ConnectionHome::Elsewhere {
            table: "contact_sync_connections",
            configured_at: "Settings > Microsoft 365 Contacts",
            issue: "MAPPS-1124",
        },
        credential_home: CredentialHome::ContactSync,
        build: ProviderBuild::Built,
    },
    ProviderDescriptor {
        provider: IntegrationProvider::Icloud,
        display_name: "iCloud Contacts",
        description: "Import contacts from an iCloud account over CardDAV, with an Apple ID \
                      and an app-specific password. Read-only: nothing is written back.",
        supported_capabilities: &[Capability::Contacts],
        polling: Some(POLLED),
        // MAPPS-1122: listed so the panel can answer "what is this organization
        // connected to" for a source that has always had its own surface and
        // never had an entry here. Like Google and Microsoft 365, the
        // connection and the credential both belong to contact sync (PMS-1341),
        // so nothing about it is settable on this surface.
        connection_home: ConnectionHome::Elsewhere {
            table: "contact_sync_connections",
            configured_at: "Settings > iCloud Contacts",
            issue: "PMS-1315",
        },
        credential_home: CredentialHome::ContactSync,
        build: ProviderBuild::Built,
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

    /// PMS-1525: every provider declaring `Invoicing` is one an issuer can
    /// actually receive it.
    ///
    /// This is the assertion whose absence let two files disagree in writing.
    /// Stripe's entry declared the capability, and `issuer_delegation`'s own
    /// comment said Stripe is never an invoicing provider - its invoicing is
    /// "pay-now links on Mokosh-issued invoices", which is what
    /// `Capability::Payments` already means. `invoice_issuer_dispatch` read the
    /// capability for Xero and QuickBooks and for nothing else, so a tenant row
    /// carrying it for Stripe claimed a delegation that never happened and
    /// would have started happening the day somebody shipped a Stripe issuer.
    ///
    /// Checked against `ExternalInvoicingProvider::parse`, the function the
    /// dispatch uses, rather than a list of names repeated here.
    #[test]
    fn only_a_provider_an_issuer_can_receive_declares_invoicing() {
        use crate::modules::billing::issuer_delegation::ExternalInvoicingProvider;
        for entry in REGISTRY {
            if entry.supports(Capability::Invoicing) {
                assert!(
                    ExternalInvoicingProvider::parse(entry.provider.as_str()).is_some(),
                    "{} declares Invoicing and no issuer can receive it",
                    entry.provider.as_str()
                );
            }
        }
    }

    /// MAPPS-1098: payment providers are not offered on the integrations
    /// page; every other provider is. Pin this per-variant so a new payment
    /// provider added without the `CredentialHome::PaymentGateway` tag
    /// (or a non-payment provider accidentally tagged with it) does not
    /// quietly cross between the two surfaces.
    #[test]
    fn is_writable_on_integrations_page_matches_credential_home() {
        for entry in REGISTRY {
            let want = matches!(entry.credential_home, CredentialHome::Integration);
            assert_eq!(
                entry.is_writable_on_integrations_page(),
                want,
                "{} exposure disagrees with its credential home",
                entry.provider.as_str()
            );
        }
    }

    /// MAPPS-1098: the two current payment providers (Stripe, PayPal) must
    /// NOT be exposed on the integrations page. A regression here means a
    /// duplicate connect button rematerialises on `Settings > Integrations`.
    #[test]
    fn stripe_and_paypal_are_not_exposed_on_integrations_page() {
        for provider in [IntegrationProvider::Stripe, IntegrationProvider::Paypal] {
            let d = descriptor(provider);
            assert!(
                !d.is_writable_on_integrations_page(),
                "{} must not appear on Settings > Integrations",
                provider.as_str()
            );
        }
    }

    /// MAPPS-1153: no provider in this registry is configured on the
    /// integrations page, and every one of them says where it IS.
    ///
    /// This replaces a test asserting the opposite for four of them, and
    /// the inversion is the end of MAPPS-1122's argument rather than a
    /// reversal of it: Connected Services is a panel that says what is
    /// connected and where each one is set up, so a provider configured
    /// there would be the exception. The payment providers are the payments
    /// surface's, the contact sources are contact sync's, and the invoice
    /// issuers are their own pages'.
    ///
    /// The second assertion is what makes the first safe. A provider that
    /// is not writable here and names no surface is unreachable: listed,
    /// unconfigurable, and pointing nowhere.
    #[test]
    fn no_provider_is_configured_on_the_integrations_page_and_each_says_where_it_is() {
        for entry in REGISTRY {
            assert!(
                !entry.is_writable_on_integrations_page(),
                "{} would be configured on the panel, which is not what the panel is for",
                entry.display_name
            );
            assert!(
                entry.setup_surface().is_some(),
                "{} is not configured here and names no page that does",
                entry.display_name
            );
        }
    }

    /// A credential home added later is not writable here until somebody
    /// says so.
    ///
    /// The predicate used to answer "anything that is not a payment
    /// gateway", so a new home became writable by default and the decision
    /// was made by omission. Asserted per home rather than per provider,
    /// because the next one will arrive without a provider carrying it yet.
    #[test]
    fn only_the_integration_credential_home_is_writable_here() {
        for home in [
            CredentialHome::PaymentGateway,
            CredentialHome::ContactSync,
            CredentialHome::InvoiceIssuer,
        ] {
            let entry = ProviderDescriptor {
                credential_home: home,
                ..*descriptor(IntegrationProvider::Google)
            };
            assert!(
                !entry.is_writable_on_integrations_page(),
                "{home:?} is configured on its own surface, not on the panel"
            );
        }
        let arrives_here = ProviderDescriptor {
            credential_home: CredentialHome::Integration,
            ..*descriptor(IntegrationProvider::Google)
        };
        assert!(
            arrives_here.is_writable_on_integrations_page(),
            "a credential that arrives in the connect request is the one case this surface serves"
        );
    }

    /// MAPPS-1102: the `point_of_sale` capability was dropped. Pin that no
    /// descriptor advertises it, so re-adding the string without re-adding
    /// the subsystem it would delegate to fails the build. The enum
    /// variant is gone; a string-level check is what survives.
    #[test]
    fn point_of_sale_is_not_supported_by_any_provider() {
        for entry in REGISTRY {
            for capability in entry.supported_capabilities {
                assert_ne!(
                    capability.as_str(),
                    "point_of_sale",
                    "{} still advertises `point_of_sale` after MAPPS-1102",
                    entry.provider.as_str()
                );
            }
        }
    }
}

#[cfg(test)]
mod mapps1121_build_state_tests {
    use super::*;

    /// A `Planned` entry names the issue that builds it.
    ///
    /// The field is the only thing tying a listed-but-absent provider to the
    /// work that makes it real; an empty one leaves the next reader grepping
    /// for whether anyone intends to build it.
    #[test]
    fn every_planned_provider_names_its_tracking_issue() {
        for entry in REGISTRY {
            if let ProviderBuild::Planned { tracked_by } = entry.build {
                assert!(
                    tracked_by.starts_with("MAPPS-") || tracked_by.starts_with("PMS-"),
                    "{} is planned but `tracked_by` is {tracked_by:?}",
                    entry.display_name
                );
            }
        }
    }

    /// Built means a client exists, and this is what stops the flag drifting
    /// from the tree.
    ///
    /// Asserted by searching the module tree for something only a real client
    /// has: Stripe and PayPal have their payment clients, Google has its
    /// contact-sync provider. A provider flipped to `Built` without one fails
    /// here rather than on a tenant's screen, which is where it failed last
    /// time (the page offered a credential field for three providers with
    /// nothing behind them).
    #[test]
    fn built_providers_have_something_behind_them() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
        let mut sources = String::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src/modules") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    sources.push_str(&std::fs::read_to_string(&path).expect("read source"));
                }
            }
        }
        // One marker per built provider: a string that only its real
        // implementation contains, not the registry's own description. Every
        // needle is assembled at runtime, because this file is inside the tree
        // being scanned and a literal would match itself: the first run of this
        // test failed on a needle written out in this very comment, which is
        // the self-match this repository has hit before in source-scanning
        // guards.
        let host = |name: &str, tld: &str| format!("{name}{tld}");
        for (provider, marker) in [
            (IntegrationProvider::Stripe, host("api.stripe", ".com")),
            (IntegrationProvider::Paypal, host("api-m.paypal", ".com")),
            (
                IntegrationProvider::Google,
                host("people.googleapis", ".com"),
            ),
            // MAPPS-1101 landed between this ticket being written and being
            // implemented, which is exactly the drift this test exists for.
            (
                IntegrationProvider::Microsoft,
                host("graph.microsoft", ".com"),
            ),
            // MAPPS-1153: the two invoice issuers, flipped once they had a
            // client, a consent round trip, a settings page and a mapping
            // surface. Their hosts were assembled from parts until now,
            // precisely so this test would not read a library-only client as
            // evidence; the parts are gone and the marker is the real host.
            (IntegrationProvider::Xero, host("api.xero", ".com")),
            (
                IntegrationProvider::Quickbooks,
                host("quickbooks.api.intuit", ".com"),
            ),
        ] {
            assert!(
                descriptor(provider).build.is_built(),
                "{provider:?} is a built provider"
            );
            assert!(
                sources.contains(&marker),
                "{provider:?} is marked Built but nothing in src/modules talks to {marker}"
            );
        }
        // Nothing is planned any more, and the rule still has to hold for
        // whatever is added next: a `Planned` entry must not be the one with
        // a client behind it.
        for entry in REGISTRY {
            if !entry.build.is_built() {
                panic!(
                    "{} is planned; add its marker above when it flips, or this test stops \
                     meaning anything",
                    entry.display_name
                );
            }
        }
    }
}

#[cfg(test)]
mod mapps1122_panel_tests {
    use super::*;

    /// Every provider with a setup surface points at its OWN page.
    ///
    /// `CredentialHome::ContactSync` names one surface for three providers,
    /// which is exactly why the kind is served per provider rather than
    /// derived from the credential home: a client routing on the home would
    /// send an iCloud admin to the Google page.
    #[test]
    fn each_setup_surface_is_distinct_and_named_for_its_provider() {
        let mut kinds: Vec<&str> = REGISTRY
            .iter()
            .filter_map(|entry| entry.setup_surface().map(|s| s.kind))
            .collect();
        let before = kinds.len();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(
            before,
            kinds.len() + 1,
            "exactly one kind is shared, by the two payment providers: {kinds:?}"
        );
        for (provider, kind) in [
            (IntegrationProvider::Stripe, "payment_gateway"),
            (IntegrationProvider::Paypal, "payment_gateway"),
            (IntegrationProvider::Google, "contact_sync_google"),
            (IntegrationProvider::Icloud, "contact_sync_icloud"),
            (IntegrationProvider::Microsoft, "contact_sync_microsoft"),
        ] {
            assert_eq!(
                descriptor(provider).setup_surface().map(|s| s.kind),
                Some(kind)
            );
        }
    }

    /// A provider with nothing behind it has nowhere to send anyone.
    ///
    /// The panel's one action is "Set up", and offering it for a provider
    /// with no page would land an operator on nothing. MAPPS-1121 says such
    /// a card is "not available yet"; this is the other half of that
    /// statement.
    ///
    /// MAPPS-1153 flipped the last two `Planned` entries, so the rule is
    /// asserted over the registry rather than against a list of names: it
    /// has to keep holding for the next provider added as planned, and a
    /// test naming Xero would have been deleted rather than kept.
    #[test]
    fn a_planned_provider_offers_no_setup_surface() {
        let mut built_with_a_surface = 0;
        for entry in REGISTRY {
            if entry.build.is_built() {
                built_with_a_surface += entry.setup_surface().is_some() as usize;
            } else {
                assert!(
                    entry.setup_surface().is_none(),
                    "{} is planned and has nowhere to send an operator",
                    entry.display_name
                );
            }
        }
        assert_eq!(
            built_with_a_surface,
            REGISTRY.len(),
            "every built provider names the page that owns it, which is what the panel links to"
        );
    }

    /// Listing a provider and letting it be changed here are different
    /// questions, and MAPPS-1098 answered both with one predicate.
    ///
    /// The payment providers are the case: they are listed, because an
    /// operator asking what the organization is connected to wants to see the
    /// two most organizations use, and they are not writable, because their
    /// lifecycle belongs to Settings > Payment Gateways.
    #[test]
    fn payment_providers_are_listed_but_not_writable_here() {
        for provider in [IntegrationProvider::Stripe, IntegrationProvider::Paypal] {
            let entry = descriptor(provider);
            assert!(
                REGISTRY.iter().any(|e| e.provider == provider),
                "listed: the panel is a list of what exists"
            );
            assert!(
                !entry.is_writable_on_integrations_page(),
                "but changed only where its credential and mode live"
            );
        }
    }

    /// iCloud is listed and is never writable here.
    ///
    /// It joined the registry for the panel's sake (MAPPS-1122), and its
    /// connection and credential both belong to contact sync (PMS-1341). An
    /// entry that was writable here would be a second place to set it up,
    /// which is the thing this page is being cured of.
    #[test]
    fn icloud_is_listed_and_managed_by_contact_sync() {
        let entry = descriptor(IntegrationProvider::Icloud);
        assert!(entry.build.is_built());
        assert!(matches!(
            entry.connection_home,
            ConnectionHome::Elsewhere {
                table: "contact_sync_connections",
                ..
            }
        ));
        assert_eq!(entry.credential_home, CredentialHome::ContactSync);
    }
}
