//! Mokosh auth: OpenID Connect provider engine.
//!
//! Pure protocol logic. Receives constructor-injected repositories, key
//! set, clock, and config; never opens a TCP socket, reads env vars, or
//! issues SQL directly.
//!
//! Each endpoint is a free async function (or a method on
//! [`OidcProvider`]) returning an `Outcome` enum that the HTTP layer
//! translates to an HTTP response.

pub mod authorize;
pub mod client_auth;
pub mod config;
pub mod discovery;
pub mod logout;
pub mod provider;
pub mod token;
pub mod tokens;
pub mod userinfo;

pub use authorize::{handle_authorize, AuthorizeOutcome, AuthorizeRequest};
pub use config::EngineConfig;
pub use discovery::openid_configuration;
pub use logout::{handle_logout, LogoutOutcome, LogoutRequest, RevokedSession};
pub use provider::OidcProvider;
pub use token::{handle_token, TokenRequest, TokenResponse};
pub use tokens::{AccessTokenClaims, IdTokenClaims, LogoutTokenClaims, MintedAccessToken};
pub use userinfo::{handle_userinfo, UserInfoResponse};
