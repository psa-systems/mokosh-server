//! Infisical secrets-management integration.
//!
//! Two layers live here:
//! - [`client::InfisicalClient`] is the runtime HTTP client used by Mokosh
//!   Server processes to fetch and write secrets via Universal Auth.
//! - [`bootstrap::bootstrap_infisical`] (and the [`dev::run_dev_bootstrap`]
//!   wrapper) drives the first-run setup of a fresh Infisical instance:
//!   admin signup, project creation, machine identity, and Universal Auth
//!   client secret.
//!
//! The bootstrap is intentionally a one-shot operation against a brand-new
//! Infisical container and is exposed to operators via the `mokosh-bootstrap`
//! CLI binary.

pub mod bootstrap;
pub mod client;
pub mod dev;

pub use bootstrap::{bootstrap_infisical, BootstrapInput, BootstrapOutput};
pub use client::InfisicalClient;
pub use dev::{run_dev_bootstrap, DevBootstrapConfig};
