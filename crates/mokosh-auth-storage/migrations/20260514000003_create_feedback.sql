-- In-app feedback inbox. Public POST /v1/feedback (anonymous OK);
-- admin GET /v1/admin/feedback + PATCH for triage status.
--
-- Submitter id is nullable so signed-out users can submit (the SPA's
-- public /feedback page works without auth). Tenant id is nullable so
-- anonymous submissions land in a shared queue rather than a
-- per-tenant one.
--
-- See docs/mokosh-fixes/04-feedback-inbox.md.

CREATE TABLE mokosh_auth.feedback (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID         REFERENCES public.tenants(id) ON DELETE SET NULL,
    submitter_id      UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    submitter_name    TEXT,
    submitter_email   TEXT,
    subject           TEXT,
    message           TEXT         NOT NULL,
    tags              TEXT[]       NOT NULL DEFAULT '{}',
    page_path         TEXT,
    user_agent        TEXT,
    ip                INET,
    status            TEXT         NOT NULL DEFAULT 'new'
                                    CHECK (status IN ('new', 'triaged', 'closed')),
    forgejo_issue_url TEXT,
    closed_by         UUID         REFERENCES mokosh_auth.users(id) ON DELETE SET NULL,
    closed_at         TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_feedback_status_created
    ON mokosh_auth.feedback (status, created_at DESC);
CREATE INDEX idx_feedback_tenant_status
    ON mokosh_auth.feedback (tenant_id, status, created_at DESC);
