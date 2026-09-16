//! PMS-1211 (PSA-70): one-way contact import from an external directory.
//!
//! Google Contacts is the only provider this epic implements. Mokosh never
//! writes back: the scope requested is `contacts.readonly` (PMS-1212), so
//! one-way is a permission rather than a promise this code keeps.
//!
//! Phase 1 is the schema (migration 220), this provider seam, and the secret
//! kind the refresh token is addressed by (`SecretKind::ContactSync`). The
//! People API client, the matching and the sync worker are PMS-1213 and
//! PMS-1215; the routes are PMS-1212. Nothing here reaches the network yet.

pub mod google;
pub mod oauth;
pub mod routes;
pub mod service;

pub use service::ContactSyncService;
pub mod provider;
