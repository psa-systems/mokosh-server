//! Mokosh auth: PostgreSQL persistence layer.
//!
//! Concrete implementations of the repository traits defined in
//! `mokosh-auth-core`. This is the only crate that links `sqlx`. All
//! migrations live under `migrations/` and are embedded with
//! `sqlx::migrate!()`.

pub mod audit;
pub mod client;
pub mod code;
pub mod conv;
pub mod entitlement;
pub mod invite;
pub mod membership;
pub mod migrations;
pub mod pool;
pub mod refresh;
pub mod session;
pub mod signup;
pub mod user;

pub use audit::PgAuditLogger;
pub use client::PgOAuthClientRepository;
pub use code::PgAuthCodeRepository;
pub use entitlement::PgEntitlementRepository;
pub use invite::PgInviteRepository;
pub use membership::PgMembershipRepository;
pub use migrations::run_migrations;
pub use pool::AuthPool;
pub use refresh::PgRefreshTokenRepository;
pub use session::PgOpSessionRepository;
pub use signup::PgSignupTokenRepository;
pub use user::PgUserRepository;
