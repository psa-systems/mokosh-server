# Tenancy

Every row Mokosh stores belongs to a tenant. A tenant is the MSP's own workspace (the MSP itself in a self-hosted single-tenant deployment, each MSP's workspace in a hosted deployment). Users belong to a tenant; so do contacts, companies, tickets, invoices, articles, and settings.

## Tenants, users, and companies

- **Tenant**: the top-level container. Everything belongs to exactly one. A deployment with the `multi-tenant` feature off has one and only one tenant; the CRUD endpoints for `/tenants` are not mounted at all in that build.
- **User**: a staff member inside a tenant. A user signs in through Bunyip (or the legacy path during migration) and carries one role.
- **Company**: a client or vendor the tenant works with. One tenant owns many companies.
- **Contact**: a person at a company, or a standalone individual. Contacts are tenant-scoped and reach the customer portal through a separate identity plane.

## Roles

Each user carries one role. The role gates which API endpoints the user can call and which panes the SPA renders. Three roles exist on the staff plane:

- **Admin**: everything inside the tenant. Billing, tenant settings, user management, feature toggles (operator-gated separately).
- **Manager**: reads every record, manages tickets and time, assigns work, grants portal access. No writes to invoices, no changes to tenant billing settings.
- **Technician**: ticket work, time logging, assigned contacts, the knowledge base. No access to billing or tenant settings.

A fourth role, **read-only**, can be granted for audit-style access: it reads everything a technician reads and nothing else. Every write endpoint refuses it. A `GET` / `HEAD` / `OPTIONS` passes through.

A fifth role lives on a separate plane: the **deployment operator**, a `platform_admins` row. This is the only persona that can change deployment-wide settings (SMTP relay, product name, application-tier secrets, feature toggles, the provider backends). It has its own sign-in at `/platform/login` and is not a tenant role. See [operations/first-run-onboarding.md](operations/first-run-onboarding.md) for the first operator setup.

## Teams

Teams group users for dispatch, SLA assignment, and queue filtering. A team belongs to a tenant and lists its members. A user can belong to many teams. Teams are optional; a single-team MSP can ignore them.

Team management is at `/api/v1/teams`; a user's own team membership is at `/api/v1/me/teams`. Both are gated to tenants where the `multi-tenant` feature is on.

## The contact plane

Contacts are a third, completely separate identity plane. A contact is a person at a client company who signs in to the customer portal. The contact plane:

- Owns its own credentials. Contacts never land in the staff `users` table. A contact's password lives on the contact row.
- Has its own session shape: shorter-lived, scoped to its company.
- Has its own two-factor enrollment and reset flows.
- Carries a distinct bearer `typ` claim, so a contact bearer cannot pass as a staff bearer and vice versa.
- Is gated by capability, not role. A contact holds capabilities like `kb:read`, `tickets:write`, `invoices:pay` granted by the MSP through a portal role.

Portal roles are tenant-scoped templates. An admin builds a role like "Billing contact" with specific capabilities, then assigns it to the contact. A contact with no portal role has no portal access at all.

Some routes are dual-plane: `/api/v1/tickets`, `/api/v1/invoices` and `/api/v1/quotes` accept either a staff bearer (which lands in staff state) or a contact bearer (which lands in contact state, filtered to the contact's company). The handler decides what the caller sees based on which bearer decoded, so one path serves both planes without a handler having to check.

## Memberships across tenants

A user in one tenant can be granted access to another through a grant invitation. The grantor's admin creates the invitation; the grantee accepts it from their inbox (or an emailed token link if the directory lookup is not configured). Accepting registers the grant in Bunyip so the grantee can switch tenants through the Bunyip account switcher.

Grants are listed at:

- `/api/v1/grants/invitations`: owner surface, admin-gated.
- `/api/v1/grants/invitations/by-token`: unauthenticated token-driven, for a first-sight grantee.
- `/api/v1/my-grants/invitations`: grantee inbox, authenticated.
- `/api/v1/my-grants`: the grantee's "leave account" surface, acting on themselves.

## Tenant scope is a compile-time invariant

Every service method inside Mokosh takes a `TenantId` whose constructor is reachable only through the resolved caller. A handler that forgets to carry the caller's tenant does not compile. This is why there is no middleware-level tenant filter: the type system enforces it. The one documented escape hatch (used by migration backfills and cross-tenant admin reads) carries its own audit trail.

What this means in practice: every list, read, and write you call through the API is scoped to the caller's tenant without the API consumer having to pass a tenant id. Pass a tenant id in a query string and the server ignores it.
