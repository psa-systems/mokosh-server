//! Tenant context for multi-tenant database operations

use uuid::Uuid;

/// Tenant context for database operations
///
/// In multi-tenant mode, this is used to set the current tenant
/// for Row Level Security (RLS) policies.
#[derive(Clone, Debug)]
pub struct TenantContext {
    /// The current tenant ID
    pub tenant_id: Uuid,
    /// The current user ID (optional)
    pub user_id: Option<Uuid>,
}

impl TenantContext {
    /// Create a new tenant context
    pub fn new(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            user_id: None,
        }
    }

    /// Create a tenant context with user
    pub fn with_user(tenant_id: Uuid, user_id: Uuid) -> Self {
        Self {
            tenant_id,
            user_id: Some(user_id),
        }
    }

    /// Get the tenant ID
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Get the user ID if set
    pub fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }
}

// PMS-262: the `single-tenant` cargo feature (and the
// `default_tenant_id()` / `Default for TenantContext` it gated) has been
// removed. That code pinned every operation to a single shared tenant
// (`00000000-0000-0000-0000-000000000001`), which is the original
// "everyone shares one tenant" design and the single biggest cross-tenant
// data-leak vector. There is deliberately no `Default` for `TenantContext`
// any more: a tenant must always be resolved from an authenticated identity,
// never fall back to a shared constant.
//
// The Bunyip default landing tenant (`Uuid::from_u128(1)`,
// `modules::auth::middleware::default_bunyip_tenant_id`) is now an
// INFRA-ONLY tenant: the only residents are platform `super_admin`s.
// `place_bunyip_user` backfills every non-admin out of it into their own
// personal tenant on next login (see `is_stuck_in_default`), so no normal
// user shares data there.
