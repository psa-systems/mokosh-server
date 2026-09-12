-- PMS-1161: tenant_invitations carries an optional team_id. When set, the
-- login-driven acceptance (auth::middleware::place_bunyip_user) adds the
-- new user to that team in the same call as the tenant grant, so the
-- three-step operator workflow (create user + assign role + add to team)
-- collapses to one invite.
--
-- Nullable because a tenant-wide role invite is still valid: an operator
-- inviting Alice as an admin with no team assignment stays a supported
-- shape. ON DELETE SET NULL because deleting a team should not invalidate
-- an in-flight invite; the invite's ROLE is what survives, and the team
-- add just becomes a no-op on accept.

ALTER TABLE tenant_invitations
    ADD COLUMN team_id UUID NULL REFERENCES teams(id) ON DELETE SET NULL;

-- Not indexed. The predicate that matters (find pending invites for a
-- team) has no caller today and would only need one row for a delete
-- cascade, which the FK handles.
