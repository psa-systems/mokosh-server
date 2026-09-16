-- PMS-1213 (PSA-70 phase 3): what the matcher and the importer need that
-- migration 220 did not carry.
--
-- Numbered 227 rather than 222: 222 to 226 are held by open branches
-- (PMS-1208, PMS-1210, BUNYIP-674), and two migrations sharing a version stop
-- every database booting (PMS-965).

-- ============================================================================
-- 1. An exact email match can still be a question
-- ============================================================================
--
-- Migration 220 said `email` never reaches the queue, because an exact match
-- links automatically. That holds for a UNIQUE match. It does not hold when
-- two Mokosh contacts share the normalized address (plus-addressing folds
-- `jo+work@` and `jo+home@` together), or when the one contact it matches is
-- already linked to a different Google record: linking either way is a guess,
-- and a guess is a merge nobody asked for. `email_ambiguous` names that case
-- rather than filing it under `phone` or `name_company`, which would tell the
-- reviewer the wrong reason.
ALTER TABLE contact_sync_candidates
    DROP CONSTRAINT contact_sync_candidates_match_reason_check;
ALTER TABLE contact_sync_candidates
    ADD CONSTRAINT contact_sync_candidates_match_reason_check CHECK (
        match_reason IN ('email_ambiguous', 'phone', 'name_company')
    );

-- ============================================================================
-- 2. The company a created contact probably belongs to (PSA-70 G)
-- ============================================================================
--
-- An imported contact's organisation is free text and is stored as
-- `contacts.company_name`, never as a link: auto-creating or auto-linking a
-- company from arbitrary strings fills a CRM with records somebody then has to
-- clean up by hand. When exactly one existing company's name matches, the
-- importer records it HERE as a suggestion for a human to confirm, and the
-- contact stays unlinked until they do. NULL is the honest answer when no
-- company, or more than one, matches.
--
-- SET NULL so deleting the company withdraws the suggestion rather than the
-- provenance row. The id is chosen by a tenant-scoped read, never taken from a
-- request, so the FK bypassing RLS (PMS-333) cannot link across tenants.
ALTER TABLE contact_sync_links
    ADD COLUMN suggested_company_id UUID REFERENCES companies(id) ON DELETE SET NULL;
