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

use super::registry::{ConnectionHome, ProviderDescriptor};

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
    pub issue: String,
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
    /// `Some` when the connection is owned by another subsystem, in which case
    /// connect, disconnect and capability changes are refused here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_elsewhere: Option<ManagedElsewhereResponse>,
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
            managed_elsewhere: match descriptor.connection_home {
                ConnectionHome::Integrations => None,
                ConnectionHome::Elsewhere {
                    table,
                    configured_at,
                    issue,
                } => Some(ManagedElsewhereResponse {
                    table: table.to_string(),
                    configured_at: configured_at.to_string(),
                    issue: issue.to_string(),
                }),
            },
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
    #[validate(length(min = 1, max = 8192))]
    pub credential: String,
    /// Omitted means every capability the provider supports, because an
    /// operator who connects an integration and is asked nothing else expects
    /// it to work. Present and empty means connected and delegated nothing.
    pub capabilities: Option<Vec<String>>,
    pub config: Option<Value>,
    pub poll_interval_minutes: Option<i32>,
}
