//! Typed tenant scoping (PMS-139 / PMS-21 AC2).
//!
//! [`TenantId`] is a newtype over `Uuid` whose only in-crate constructor
//! ([`TenantId::new`]) is `pub(crate)`, and the only thing that calls it is
//! [`TenantScoped::tenant`] on an already-authenticated [`CurrentUser`]. So a
//! `TenantId` cannot be conjured from arbitrary request input: it always
//! traces back to the caller's verified tenant claim.
//!
//! Service methods that scope by tenant take `tenant_id: TenantId` rather than
//! a bare `Uuid`, which makes "forgot to scope" or "passed the wrong id" a
//! **compile error** at the call site instead of a silent cross-tenant leak.
//!
//! Because `TenantId` is a `#[sqlx(transparent)]` newtype it binds to SQL
//! exactly like the underlying `Uuid` (`.bind(tenant_id)` is unchanged), and
//! it `Deref`s to `Uuid` so the rare leaf that genuinely needs the raw value
//! (a struct field, an equality check) can reach it via `*tenant_id` or
//! [`TenantId::get`].

use std::fmt;

use uuid::Uuid;

use super::CurrentUser;

/// An authenticated tenant scope. See module docs.
///
/// Tenant scoping is enforced at the type level (PMS-139): a service method
/// that takes a `TenantId` cannot be called with a bare `Uuid`, so forgetting
/// to scope - or passing the wrong id - is a compile error at the call site
/// rather than a silent cross-tenant leak.
///
/// The only public constructor is the explicitly-named escape hatch; request
/// handlers obtain their scope from an authenticated `CurrentUser`:
///
/// ```
/// use mokosh_server::modules::auth::TenantId;
/// let scope = TenantId::from_trusted(uuid::Uuid::nil());
/// assert_eq!(scope.get(), uuid::Uuid::nil());
/// ```
///
/// A raw `Uuid` is rejected where a `TenantId` is required - this is the
/// guarantee, pinned as a compile-fail test:
///
/// ```compile_fail
/// use mokosh_server::modules::auth::TenantId;
/// fn scoped(_t: TenantId) {}
/// scoped(uuid::Uuid::nil()); // error[E0308]: expected `TenantId`, found `Uuid`
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(transparent)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Wrap a raw tenant `Uuid`. Crate-internal on purpose: the only caller
    /// is [`TenantScoped::tenant`], so within the server a `TenantId` can only
    /// be produced from an authenticated [`CurrentUser`]. External crates
    /// (and the cross-tenant escape hatch) go through [`TenantId::from_trusted`].
    pub(crate) fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// The raw tenant `Uuid`. Prefer threading `TenantId` through call sites;
    /// reach for this only at the leaves (building a response struct, an
    /// equality check, a log field).
    pub fn get(self) -> Uuid {
        self.0
    }

    /// **Escape hatch.** Build a `TenantId` from a `Uuid` that did *not* come
    /// from the request's own tenant claim. This is the explicitly-named seam
    /// the typed-scoping guarantee permits, for the two cases that legitimately
    /// need it:
    ///
    /// * a **super-admin cross-tenant** operation, where the target tenant is a
    ///   validated path/query parameter gated on role (not the caller's claim);
    /// * **tests** and background/bootstrap jobs that have no request context.
    ///
    /// It is deliberately verbose and greppable: a reviewer should be able to
    /// audit every call. Never pass unvalidated request input here.
    pub fn from_trusted(id: Uuid) -> Self {
        Self(id)
    }
}

impl std::ops::Deref for TenantId {
    type Target = Uuid;
    fn deref(&self) -> &Uuid {
        &self.0
    }
}

/// Unwrap to the raw tenant `Uuid`. Lets `Database::begin_with_tenant` accept a
/// `TenantId` or a bare `Uuid` uniformly (`impl Into<Uuid>`), so RLS-GUC call
/// sites pass `tenant_id` unchanged regardless of which type they hold.
impl From<TenantId> for Uuid {
    fn from(t: TenantId) -> Uuid {
        t.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Produce the typed [`TenantId`] for an authenticated caller. Implemented for
/// [`CurrentUser`], which every auth extractor (`RequireAuth`, `TenantScope`,
/// the `RequireModuleEnabled` family) carries, so a handler reaches its scope
/// uniformly via `user.tenant()` regardless of which guard it used.
pub trait TenantScoped {
    fn tenant(&self) -> TenantId;
}

impl TenantScoped for CurrentUser {
    fn tenant(&self) -> TenantId {
        TenantId::new(self.tenant_id)
    }
}
