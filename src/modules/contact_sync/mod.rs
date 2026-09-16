//! PMS-1211 (PSA-70): one-way contact import from an external directory.
//!
//! Google Contacts is the only provider this epic implements. Mokosh never
//! writes back: the scope requested is `contacts.readonly` (PMS-1212), so
//! one-way is a permission rather than a promise this code keeps.
//!
//! * `provider`: the read-only seam, `google` its one implementation
//!   (PMS-1211, PMS-1213).
//! * `oauth`, `service`, `routes`: connecting and keeping a usable token
//!   (PMS-1212).
//! * `normalize`, `matching`, `mapping`: what a source record means to the
//!   CRM, all pure (PMS-1213).
//! * `sync`: one pass of one connection (PMS-1213). Scheduling and run
//!   tracking are PMS-1215.
//! * `locks`: an edit in Mokosh locks the field against the source; the
//!   service's provenance, unlink and data-removal methods are the rest of what
//!   decides whether a person trusts the integration (PMS-1214).

pub mod google;
pub mod locks;
pub mod mapping;
pub mod matching;
pub mod normalize;
pub mod oauth;
pub mod provider;
pub mod routes;
pub mod service;
pub mod sync;

pub use service::ContactSyncService;
