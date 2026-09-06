//! mokosh-contact-login prompt 007: MSP-admin portal-role management.
//!
//! Owns the `portal_roles` CRUD surface + the human-facing capability
//! label list the SPA renders as checkbox labels in the role editor.
//! Reads and writes stay per-tenant; deletes fail closed when the role
//! is still assigned to any contact so an admin cannot silently strand
//! portal users mid-session. The `capability_labels` submodule is the
//! single source of truth for how a capability key renders in the UI;
//! `ALL_CAPABILITIES` (in `contact_portal::capabilities`) is still the
//! single source of truth for what keys exist.

pub mod capability_labels;
pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::portal_role_routes;
pub use service::PortalRoleService;
