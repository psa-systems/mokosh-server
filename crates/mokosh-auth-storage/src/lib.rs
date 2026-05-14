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
pub mod feedback;
pub mod invite;
pub mod membership;
pub mod mfa_challenge;
pub mod migrations;
pub mod org_invitation;
pub mod password_reset;
pub mod pool;
pub mod recovery_code;
pub mod refresh;
pub mod session;
pub mod signup;
pub mod tenant;
pub mod totp;
pub mod trusted_device;
pub mod user;

pub use audit::PgAuditLogger;
pub use client::PgOAuthClientRepository;
pub use code::PgAuthCodeRepository;
pub use entitlement::PgEntitlementRepository;
pub use feedback::PgFeedbackRepository;
pub use invite::PgInviteRepository;
pub use membership::PgMembershipRepository;
pub use mfa_challenge::PgMfaChallengeRepository;
pub use migrations::run_migrations;
pub use org_invitation::PgOrgInvitationRepository;
pub use password_reset::PgPasswordResetTokenRepository;
pub use pool::AuthPool;
pub use recovery_code::PgRecoveryCodeRepository;
pub use refresh::PgRefreshTokenRepository;
pub use session::PgOpSessionRepository;
pub use signup::PgSignupTokenRepository;
pub use tenant::PgTenantRepository;
pub use totp::PgTotpRepository;
pub use trusted_device::PgTrustedDeviceRepository;
pub use user::PgUserRepository;
