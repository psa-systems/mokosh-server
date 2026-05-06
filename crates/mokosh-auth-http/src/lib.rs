//! Mokosh auth: Axum HTTP surface.
//!
//! The only crate that knows about Axum, cookies, request parsing, and
//! HTTP error mapping. Composing the router happens through
//! [`build_router`], which takes a populated `OidcProvider` plus the
//! `LocalAuth` service for the OP's own login UI.

pub mod cookies;
pub mod errors;
pub mod extractors;
pub mod local_auth;
pub mod router;

pub mod handlers {
    pub mod auth;
    pub mod discovery;
    pub mod oidc;
}

pub use cookies::{clear_op_session_cookie, set_op_session_cookie, OP_SESSION_COOKIE};
pub use errors::HttpError;
pub use local_auth::{LocalAuth, LocalLoginRequest};
pub use router::{build_router, AuthHttpState};
