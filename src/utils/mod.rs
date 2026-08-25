//! Utility modules for Mokosh Server

pub mod client_ip;
pub mod crypto;
pub mod datetime;
// PMS-902: self-hosted vs SaaS. Decides whether mokosh owns platform identity
// or federates it to Bunyip, which is what makes local-account email moot.
pub mod deployment;
pub mod email;
pub mod error;
pub mod geoip;
pub mod html;
// Shared IP classification (PMS-805): one `is_non_public_ip`, used by the
// login-location check and by the website probe's SSRF guard.
pub mod net;
pub mod pagination;
#[cfg(feature = "server")]
pub mod security_headers;
// TOTP (RFC 6238) + MFA recovery codes for the legacy HS256 auth flow.
// Relocated here from the removed `mokosh-auth-crypto` crate (PMS-295): the
// legacy login path is the only consumer, so the primitives live in the host
// crate now that the mokosh-auth (mechanism 2) workspace members are gone.
pub mod recovery;
// PMS-924: invisible-character normalization plus the JSON-body middleware
// that applies it before any handler deserializes a request.
pub mod text;
pub mod totp;
pub mod validation;

// Re-exports
pub use error::{AppError, AppResult};
pub use pagination::{PaginatedResponse, PaginationParams};
