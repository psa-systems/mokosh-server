//! Shared DTOs for the Mokosh PSA platform.
//!
//! These types are the wire-format contract between `mokosh-server`
//! (the REST API) and `mokosh-apps` (the WASM frontend). Both
//! crates depend on this one; previously the model trees were
//! byte-identical copies maintained by hand. See cross-cutting issue
//! `#12` in `dev-docs/codebase-state.md` and PMS-129.
//!
//! Module shape mirrors the consuming feature modules:
//!
//! ```text
//! mokosh_server::modules::<m>::models -> re-exports mokosh_types::<m>::*
//! mokosh_apps::modules::<m>::models -> ditto
//! ```
//!
//! Nothing in this crate touches a database, a network socket, an
//! axum extractor, or an HTTP response. Add `serde`-derive,
//! `validator::Validate`, and pure helper impls; everything else
//! belongs in the server or client crate.

pub mod auth;
pub mod contacts;
pub mod tenants;
pub mod tickets;
pub mod time_tracking;

/// Shared serde default: `#[serde(default = "crate::default_true")]`.
/// Several request DTOs treat a missing boolean flag as `true`; this is
/// the single canonical implementation rather than a per-module copy.
pub(crate) fn default_true() -> bool {
    true
}
