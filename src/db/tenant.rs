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

/// Default tenant ID for single-tenant mode
#[cfg(feature = "single-tenant")]
pub fn default_tenant_id() -> Uuid {
    // A fixed UUID for single-tenant installations
    // This allows the same schema to work in both modes
    Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
}

#[cfg(feature = "single-tenant")]
impl Default for TenantContext {
    fn default() -> Self {
        Self::new(default_tenant_id())
    }
}
