//! Form DTOs.
//!
//! PMS-898: the wire types moved to `mokosh_types::forms` and are re-exported
//! here, so every call site in this module tree keeps its import path. They
//! were the last hand-copy across the repo boundary; mokosh-apps carried two
//! of them.
//!
//! What stays below is the one type that is not a wire type.

pub use mokosh_types::forms::*;

use uuid::Uuid;

/// What a presented token resolves to. Internal: never serialised, because
/// every field is a tenant-internal id.
#[derive(Debug, Clone)]
pub struct ResolvedRequestToken {
    pub token_id: Uuid,
    pub tenant_id: crate::modules::auth::TenantId,
    pub form_definition_id: Uuid,
    pub company_id: Uuid,
    pub contact_id: Option<Uuid>,
    /// The MSP user who issued the link. Becomes the created ticket's
    /// `created_by_id`, since the submitter is a client with no `users` row
    /// and that column is NOT NULL.
    pub created_by_id: Uuid,
}
