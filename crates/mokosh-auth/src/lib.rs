//! Mokosh auth: umbrella crate.
//!
//! Re-exports the public surface and provides bootstrap helpers so that
//! `mokosh-server` only depends on this single crate.

pub use mokosh_auth_core as core;
pub use mokosh_auth_crypto as crypto;
pub use mokosh_auth_federation as federation;
pub use mokosh_auth_http as http;
pub use mokosh_auth_oidc as oidc;
pub use mokosh_auth_storage as storage;

pub mod config;

pub use config::AuthConfig;
