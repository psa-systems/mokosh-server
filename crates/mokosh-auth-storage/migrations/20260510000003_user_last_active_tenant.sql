-- Track the tenant a user was most recently acting under. Read at
-- /v1/auth/login when the request omits an explicit tenant_id, and
-- updated by /v1/auth/active-tenant on every tenant switch. NULL
-- means "fall back to the user's home tenant" (mokosh_auth.users.tenant_id).
--
-- See docs/mokosh-auth/10-memberships-and-self-signup.md (phase 4).

ALTER TABLE mokosh_auth.users
    ADD COLUMN last_active_tenant UUID
        REFERENCES public.tenants(id) ON DELETE SET NULL;
