//! PMS-450 phase 1: email-to-ticket intake.
//!
//! External mail gateways (postfix MDA hook, Cloudron, Microsoft
//! Graph subscription forwarder) parse an inbound email and POST
//! the structured payload to `/api/v1/email-intake`, authenticated
//! with a tenant-scoped bearer token from
//! [`tenant_intake_tokens`]. The service dedupes by Message-Id,
//! threads against prior tickets via the `references` array
//! (returns the existing ticket id; commenting on it is Phase 2),
//! looks up the contact by From: address inside the caller's tenant
//! scope, and creates a `source='email'` ticket attributed to a
//! tenant admin (mirroring `create_portal_ticket`'s creator-lookup
//! pattern).

mod models;
mod routes;
mod service;

pub use routes::{email_intake_routes, EmailIntakeRouterState};
pub use service::EmailIntakeService;
