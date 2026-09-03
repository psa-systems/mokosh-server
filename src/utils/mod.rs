//! Utility modules for Mokosh Server

// PMS-789: the deployment's product name, cached in-process so the DB-free
// paths (the catch-all 404 page, mail built inside an open transaction) can
// read it synchronously.
pub mod app_name;
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
pub mod login_location;
// PMS-941: the one image allowlist every publicly-readable image route shares
// (tenant logo, KB article image, ticket inline image). SVG is refused there.
pub mod inline_image;
// Shared IP classification (PMS-805): one `is_non_public_ip`, used by the
// login-location check and by the website probe's SSRF guard.
pub mod net;
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
// PMS-924: invisible-character normalization plus the JSON-body middleware
// that applies it before any handler deserializes a request.
pub mod text;
pub mod totp;
pub mod validation;

// Re-exports
pub use error::{AppError, AppResult};
pub use pagination::{PaginatedResponse, PaginationParams};
