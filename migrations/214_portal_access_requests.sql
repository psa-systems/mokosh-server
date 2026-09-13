-- PMS-1187: a portal contact can ask for access, and the MSP is told.
--
-- A contact who lacks a capability sees an empty screen and has no way to say
-- so. Their options are to guess which person at the MSP to email, or to give
-- up; the MSP hears nothing either way, because nothing anywhere records that
-- a customer tried to reach something and could not. PMS-1186 closes the one
-- case where the MSP had already designated a billing contact. It cannot close
-- the general one: a colleague who needs invoices, a new hire who needs
-- tickets, a contact whose access was never set up for what they now do.
--
-- The row records the AREA asked for, not a capability name. A customer asking
-- for "invoices" should not have to know that `invoices:pay` and
-- `invoices:download_pdf` are separate strings; the MSP granting it picks the
-- role. The areas are the capability domains (`<domain>:<action>`), so the set
-- is closed and the server validates against it rather than storing free text.
CREATE TABLE portal_access_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    -- Denormalised from the contact so a request survives the contact being
    -- re-homed, and so the staff list can be read per company without a join
    -- through a mirror that PMS-1069 already warns about.
    company_id UUID REFERENCES companies(id) ON DELETE SET NULL,
    area VARCHAR(32) NOT NULL,
    note TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'open' CHECK (
        status IN ('open', 'granted', 'declined', 'withdrawn')
    ),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Who answered it, and when. NULL while it is open. `users` because only
    -- staff resolve a request; a contact withdrawing their own leaves this
    -- NULL and the status says which happened.
    resolved_by_id UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ
);

-- One OPEN request per contact per area. A customer pressing the button twice
-- gets the same row rather than a second task for the MSP, which is also what
-- stops this being a way to generate mail. Resolved rows are kept, and a
-- contact whose access is revoked later can ask again.
CREATE UNIQUE INDEX idx_portal_access_requests_open
    ON portal_access_requests (tenant_id, contact_id, area)
    WHERE status = 'open';

-- The staff read: what is outstanding, newest first, for a tenant or one
-- contact.
CREATE INDEX idx_portal_access_requests_tenant
    ON portal_access_requests (tenant_id, status, requested_at DESC);
CREATE INDEX idx_portal_access_requests_contact
    ON portal_access_requests (contact_id);

ALTER TABLE portal_access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_access_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON portal_access_requests
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );
