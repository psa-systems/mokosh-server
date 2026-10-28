//! DTOs for the integrations surface (PMS-1310).
//!
//! The vocabulary itself ([`Capability`], [`IntegrationProvider`],
//! [`IntegrationStatus`]) comes from `mokosh-types`, so the client renders the
//! same labels the server stores. What is composed here is the CATALOG: the
//! registry's declaration of what each provider supports joined to this
//! tenant's row, because a page that offered a capability the server would
//! refuse would be a page nobody could trust.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use validator::Validate;

pub use mokosh_types::integrations::{Capability, IntegrationProvider, IntegrationStatus};

use super::registry::{ConnectionHome, CredentialHome, ProviderDescriptor};

/// One capability, as the checkbox list renders it.
///
/// `label` and `description` travel with the key rather than being looked up
/// client-side, the `portal_roles` `CapabilityDescriptor` arrangement: one edit
/// to the enum moves the whole surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDescriptorResponse {
    pub key: String,
    pub label: String,
    pub description: String,
}

impl From<Capability> for CapabilityDescriptorResponse {
    fn from(capability: Capability) -> Self {
        Self {
            key: capability.as_str().to_string(),
            label: capability.label().to_string(),
            description: capability.description().to_string(),
        }
    }
}

/// Where a provider's connection is managed, when it is not managed here.
///
/// Served rather than inferred, so the page can name the settings screen that
/// owns it instead of showing a Connect button that would 409. The issue is
/// included because the honest answer to "why is this one different" is the
/// ticket that changes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedElsewhereResponse {
    pub table: String,
    pub configured_at: String,
}

/// Where a provider's credential is entered, when it is not entered here
/// (PMS-1447).
///
/// Served rather than inferred, for the same reason
/// [`ManagedElsewhereResponse`] is: a client cannot tell whether to render a
/// credential field without this, and the alternative is a provider-to-surface
/// table in the client that the server already owns. PMS-1312 is why that would
/// not survive: it moved the payment providers' CONNECTION into `integrations`
/// while leaving their CREDENTIAL on the payments surface, so any client-side
/// copy of this mapping was wrong the day it shipped.
///
/// `kind` is for a client that branches, `entered_at` is for one that has to
/// name the screen. Both, because a page needs to do both and deriving one from
/// the other is how the two drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialElsewhereResponse {
    pub kind: String,
    pub entered_at: String,
}

/// The poll setting a provider offers, absent for one nothing polls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollingResponse {
    pub default_minutes: i32,
    pub min_minutes: i32,
}

/// One row of the integrations page: what the provider is, what it can be
/// handed, and what this tenant has handed it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationResponse {
    pub provider: IntegrationProvider,
    pub display_name: String,
    pub description: String,
    /// What this build can hand to the provider. `enabled_capabilities` is
    /// always a subset of these keys.
    pub supported_capabilities: Vec<CapabilityDescriptorResponse>,
    /// What this tenant has handed over. Empty for a provider with no row.
    pub enabled_capabilities: Vec<String>,
    pub status: IntegrationStatus,
    /// The settings surface that owns this provider's setup, and the one
    /// action the panel offers (MAPPS-1122). `None` for a provider with
    /// nowhere to send an operator yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<SetupSurfaceResponse>,
    /// Whether this provider's lifecycle can be CHANGED through this surface
    /// (MAPPS-1129).
    ///
    /// `false` means the four per-provider routes answer 404 for it and the
    /// panel's job here is to say what it is connected to and link to the
    /// surface in `setup`. Served rather than derived, for the reason
    /// `available` and `credential_elsewhere` are (PMS-1447): a client cannot
    /// work it out from a provider name, and the one that tried rendered
    /// capability checkboxes, Connect and Disconnect on Stripe and PayPal,
    /// whose every call `parse_provider` refuses.
    ///
    /// It is the same predicate that route refuses on, so the two cannot drift
    /// into a surface that offers a control the server will not take.
    pub configurable_here: bool,
    /// Whether this build has anything behind the provider (MAPPS-1121).
    /// `false` means the entry exists so its capabilities can be named, and
    /// connect and capability changes are refused: a client renders it as not
    /// available rather than offering a credential field whose value nothing
    /// would read. Served rather than derived from the provider name, the
    /// reason `credential_elsewhere` is (PMS-1447).
    pub available: bool,
    /// `Some` when the connection is owned by another subsystem, in which case
    /// connect, disconnect and capability changes are refused here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_elsewhere: Option<ManagedElsewhereResponse>,
    /// `Some` when the credential is entered on another settings surface, in
    /// which case `connect` here takes none and refuses one that is sent.
    /// Absent means the credential arrives in the connect request, so a client
    /// that renders a credential field exactly when this is absent is right by
    /// construction rather than by a list (PMS-1447).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_elsewhere: Option<CredentialElsewhereResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub polling: Option<PollingResponse>,
    /// The tenant's override, or `None` to mean the registry's default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_interval_minutes: Option<i32>,
    /// Non-secret settings only. A credential here would be a defect; see
    /// migration 252's header.
    pub config: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnected_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Where a provider is set up, as the panel renders it (MAPPS-1122).
///
/// `kind` is what the client routes on and `label` is what a reader sees. Two
/// fields because the prose has already changed once ("Settings > Contact
/// sync" named one page for three providers), and a client routing on prose
/// would have broken when it did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupSurfaceResponse {
    pub kind: String,
    pub label: String,
}

impl From<crate::modules::integrations::registry::SetupSurface> for SetupSurfaceResponse {
    fn from(surface: crate::modules::integrations::registry::SetupSurface) -> Self {
        Self {
            kind: surface.kind.to_string(),
            label: surface.label.to_string(),
        }
    }
}

/// The descriptor's credential home as the response carries it.
///
/// A free function rather than a method on the descriptor so the mapping from
/// "which home" to "what the client is told" lives beside the DTO it fills,
/// which is where a reader looking at the JSON will come looking for it.
fn credential_elsewhere(descriptor: &ProviderDescriptor) -> Option<CredentialElsewhereResponse> {
    // MAPPS-1153: composed from the HOME, and labelled from the provider's
    // own surface when it has one.
    //
    // It used to be composed from `entered_at` alone, which made the home's
    // one string do a per-provider job: `ContactSync` answers "Settings >
    // Google Contacts" for all three contact sources, so iCloud's card
    // named Google's page. `InvoiceIssuer` cannot have such a string at all
    // - nothing is entered, and the two providers have different pages -
    // which is what made the mismatch visible.
    //
    // The condition is now the home itself, so a provider whose credential
    // does NOT arrive in the connect request always says so, and the label
    // comes from `setup_surface` when there is one.
    if descriptor.credential_home == CredentialHome::Integration {
        return None;
    }
    let entered_at = descriptor
        .setup_surface()
        .map(|surface| surface.label.to_string())
        .or_else(|| descriptor.credential_home.entered_at().map(str::to_string))
        .unwrap_or_else(|| "its own settings page".to_string());
    Some(CredentialElsewhereResponse {
        kind: descriptor.credential_home.as_str().to_string(),
        entered_at,
    })
}

impl IntegrationResponse {
    /// The row as it reads for a tenant that has installed nothing: the
    /// registry's half filled in and the tenant's half empty.
    ///
    /// A provider with no row is `not_connected` rather than absent from the
    /// list, because the page's job is to show what COULD be connected.
    pub fn not_installed(descriptor: &ProviderDescriptor) -> Self {
        Self {
            provider: descriptor.provider,
            display_name: descriptor.display_name.to_string(),
            description: descriptor.description.to_string(),
            supported_capabilities: descriptor
                .supported_capabilities
                .iter()
                .copied()
                .map(CapabilityDescriptorResponse::from)
                .collect(),
            enabled_capabilities: Vec::new(),
            status: IntegrationStatus::NotConnected,
            setup: descriptor.setup_surface().map(SetupSurfaceResponse::from),
            configurable_here: descriptor.is_writable_on_integrations_page(),
            available: descriptor.build.is_built(),
            managed_elsewhere: match descriptor.connection_home {
                ConnectionHome::Integrations => None,
                ConnectionHome::Elsewhere {
                    table,
                    configured_at,
                } => Some(ManagedElsewhereResponse {
                    table: table.to_string(),
                    configured_at: configured_at.to_string(),
                }),
            },
            credential_elsewhere: credential_elsewhere(descriptor),
            polling: descriptor.polling.map(|polling| PollingResponse {
                default_minutes: polling.default_minutes,
                min_minutes: polling.min_minutes,
            }),
            poll_interval_minutes: None,
            config: Value::Object(Default::default()),
            connected_at: None,
            disconnected_at: None,
            last_error: None,
        }
    }
}

/// The `integrations` row as read back.
///
/// Its own struct rather than decoding straight into [`IntegrationResponse`],
/// because the response carries the registry's half too and that half has no
/// column.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IntegrationRow {
    #[allow(dead_code)]
    pub id: Uuid,
    pub provider: String,
    pub status: String,
    pub config: Value,
    pub enabled_capabilities: Vec<String>,
    pub poll_interval_minutes: Option<i32>,
    pub connected_at: Option<DateTime<Utc>>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

/// PUT body: what this tenant hands to the provider, and the non-secret
/// settings it runs with.
///
/// Semantically a partial update, the `UpdatePortalRoleRequest` shape: a field
/// left `None` keeps its value. An EMPTY `capabilities` is meaningful here and
/// is accepted, unlike a portal role's, because handing a provider nothing
/// while keeping it connected is a real state: it is how an operator suspends a
/// delegation without throwing the credential away.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateIntegrationRequest {
    pub capabilities: Option<Vec<String>>,
    pub config: Option<Value>,
    /// `Some(None)` clears the override back to the registry's default;
    /// absent leaves it alone. The double option is the PMS-344 shape.
    #[serde(default, deserialize_with = "mokosh_types::deserialize_double_option")]
    pub poll_interval_minutes: Option<Option<i32>>,
}

/// POST /connect body: the credential, and optionally the delegation to start
/// with.
///
/// `credential` is an opaque string as far as this subsystem is concerned. It
/// goes straight to the secrets provider and is never stored on the row, never
/// logged and never served back, which is what lets each provider ticket decide
/// its own shape (an API key, a token pair, an OAuth grant) without this code
/// learning any of them.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ConnectIntegrationRequest {
    /// The credential to store, for a provider whose
    /// [`CredentialHome`](super::registry::CredentialHome) is this surface.
    ///
    /// Optional because PMS-1312 made whether one is needed a property of the
    /// provider: a payment gateway's key, webhook secret and per-provider
    /// settings are entered under Settings > Payment gateways, so `connect` here
    /// refuses a credential rather than writing one to an address nothing reads.
    /// A provider that does need one is refused without it, so the requirement
    /// did not become optional, only per provider.
    #[validate(length(min = 1, max = 8192))]
    pub credential: Option<String>,
    /// Omitted means every capability the provider supports, because an
    /// operator who connects an integration and is asked nothing else expects
    /// it to work. Present and empty means connected and delegated nothing.
    pub capabilities: Option<Vec<String>>,
    pub config: Option<Value>,
    pub poll_interval_minutes: Option<i32>,
}
