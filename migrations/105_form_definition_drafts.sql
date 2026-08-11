-- PMS-759: server-side drafts for the request-form builder.
--
-- PMS-754 already autosaves the builder to `localStorage` on every change, and
-- that stays: a closed tab, a route change and a crash do not wait for a timer,
-- and a network write cannot be made synchronous on unload. What it cannot do
-- is follow the user to another machine, which is the requirement this table
-- exists for.
--
-- A draft is deliberately NOT a `form_definitions` row with a status column.
-- Every existing query filters `is_active`, the request-link issuer resolves a
-- definition by id and would happily send a half-built one, and `form_fields`
-- carries NOT NULL constraints a half-built form cannot satisfy. As its own
-- record, "a draft cannot be sent to a client" needs no enforcement code.

CREATE TABLE form_definition_drafts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The draft's owner. Drafts are private to the user who wrote them: a
    -- half-built form is working state, not a shared document, and sharing one
    -- needs an answer for concurrent edits that single ownership does not.
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The definition being edited, or NULL while the form is still new and has
    -- never been created. CASCADE because a draft for a deleted definition is
    -- unreachable by construction: the editor can only be opened from a row
    -- that still exists.
    form_definition_id UUID REFERENCES form_definitions(id) ON DELETE CASCADE,
    -- The editor's own snapshot, opaque here. Re-declaring the builder's shape
    -- in Rust would be a second copy to keep in step and buys nothing: nothing
    -- server-side reads inside it except `name`, for the drafts list. Its size
    -- IS bounded, in the service, because it is a client-supplied blob.
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One live draft per user per form. Two partial indexes rather than one plain
-- UNIQUE because NULLs are distinct in a unique index, so a plain constraint
-- would let a user accumulate an unbounded pile of "new form" drafts, one per
-- keystroke batch. Split this way each half is also a valid `ON CONFLICT`
-- inference target, which is what makes the autosave an upsert rather than a
-- read-then-write race.
CREATE UNIQUE INDEX idx_form_drafts_owner_definition
    ON form_definition_drafts(tenant_id, user_id, form_definition_id)
    WHERE form_definition_id IS NOT NULL;

CREATE UNIQUE INDEX idx_form_drafts_owner_new
    ON form_definition_drafts(tenant_id, user_id)
    WHERE form_definition_id IS NULL;

-- The drafts list: one user's drafts, most recently touched first.
CREATE INDEX idx_form_drafts_owner_recent
    ON form_definition_drafts(tenant_id, user_id, updated_at DESC);

-- Fail-closed tenant isolation, same shape as `form_request_tokens`
-- (migration 101). Ownership by user is enforced in the service on top of
-- this: RLS is the tenant boundary, not the per-user one.
ALTER TABLE form_definition_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_definition_drafts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON form_definition_drafts
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
