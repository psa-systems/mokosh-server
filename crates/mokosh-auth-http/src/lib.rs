//! Mokosh auth: Axum HTTP surface.
//!
//! The only crate that knows about Axum, cookies, request parsing, and
//! HTTP error mapping. Composing the router happens through
//! [`build_router`], which takes a populated `OidcProvider` plus the
//! `LocalAuth` service for password-based logins.

pub mod cookies;
pub mod email;
pub mod errors;
pub mod extractors;
pub mod local_auth;
pub mod rate_limit;
pub mod router;

pub mod handlers {
    pub mod auth;
    pub mod discovery;
    pub mod invites;
    pub mod oidc;
    pub mod sessions;
    pub mod signup;
    pub mod tenants;
    pub mod users;
}

pub use cookies::{clear_op_session_cookie, set_op_session_cookie, OP_SESSION_COOKIE};
pub use email::{LogMailer, Mailer};
pub use errors::HttpError;
pub use local_auth::{LocalAuth, LocalLoginRequest};
pub use rate_limit::{RateLimited, RateLimiter};
pub use router::{
    build_router, AuthHttpState, PersonalTenantCreator, TenantInfoLookup, TenantNameLookup,
};
