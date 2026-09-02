//! Re-export of the shared auth DTOs from `mokosh-types`.
//!
//! The actual type definitions live in the workspace `mokosh-types`
//! crate so `mokosh-apps` can consume them without copy-paste
//! (PMS-129 / cross-cutting issue #12). This file stays in place so
//! `super::models::*` paths inside the auth module continue to
//! resolve.

pub use mokosh_types::auth::*;
