//! PMS-450 / PMS-469: email-to-ticket intake.
//!
//! External mail gateways (postfix MDA hook, Cloudron, Microsoft
//! Graph subscription forwarder) parse an inbound email and POST
//! the structured payload to `/api/v1/email-intake`, authenticated
//! with a tenant-scoped bearer token from `tenant_intake_tokens`.
//! The service dedupes by Message-Id, threads against prior tickets
//! via the `references` array, looks up the contact by From:
//! address inside the caller's tenant scope, and creates a
//! `source='email'` ticket attributed to a tenant admin (mirroring
//! `create_portal_ticket`'s creator-lookup pattern).
//!
//! PMS-469 phase-2 follow-ups landed on top: a threading hit now
//! appends the body as a `note_type='public'` comment on the matched
//! ticket (`comment_added=true` in the response); unknown-sender
//! intakes auto-create a contact under the per-tenant
//! `email_intake/default_company_id` setting (preserving the
//! Phase 1 422 posture when that setting is unset); every intake
//! call writes an `email_intake_log` row at the top of the flow that
//! the admin GET `/email-intake-log/{id}` endpoint reads.

mod models;
mod routes;
mod service;

pub use routes::{email_intake_routes, EmailIntakeRouterState};
pub use service::EmailIntakeService;
