//! Utility modules for Mokosh Server

pub mod client_ip;
pub mod crypto;
pub mod datetime;
pub mod email;
pub mod error;
pub mod geoip;
pub mod html;
pub mod login_location;
pub mod pagination;
// PMS-729 phase 2 H5: shared password-strength policy consumed by every
// portal password write site (setup, reset, change). Agent surface will
// migrate onto this in a follow-up.
pub mod password_policy;
#[cfg(feature = "server")]
pub mod security_headers;
// TOTP (RFC 6238) + MFA recovery codes for the legacy HS256 auth flow.
// Relocated here from the removed `mokosh-auth-crypto` crate (PMS-295): the
// legacy login path is the only consumer, so the primitives live in the host
// crate now that the mokosh-auth (mechanism 2) workspace members are gone.
pub mod recovery;
pub mod totp;
pub mod validation;

// Re-exports
pub use error::{AppError, AppResult};
pub use pagination::{PaginatedResponse, PaginationParams};
