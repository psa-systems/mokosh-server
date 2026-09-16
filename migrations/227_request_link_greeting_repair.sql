-- PMS-1237 finding 1: repair a request-link template that never picked up
-- the salutation greeting.
--
-- Migration 106 (PMS-774) moved the greeting word out of the composer and
-- into the template, replacing the literal `{{display_name}},` opening of
-- `forms.request_link` with `{{salutation}},`. Its WHERE clause matched the
-- exact body migration 103 had left, per the migration-096 contract: a
-- tenant that had customised its copy of the template through the
-- notification CRUD API (or between 103 and 106 landing) kept its own
-- wording and was correctly left alone.
--
-- What it does NOT leave alone correctly is any row that still opened on
-- `{{display_name}},` verbatim: `FormsService::queue_request_link_email`
-- (`src/modules/forms/request_links.rs`) now always supplies `display_name`
-- as the bare name (empty string when the recipient is not a known contact)
-- and relies on a `{{salutation}}` placeholder to supply the greeting word,
-- exactly as 106's own commentary describes. A row 106 did not touch still
-- names `{{display_name}}` as its own greeting, so an anonymous request-link
-- send now opens on a bare "," with no word before it, and a known-contact
-- send opens on "David," with no "Hello". No migration since 106 has touched
-- these rows.
--
-- Repaired as a fragment replace, not a whole-body match, so it heals every
-- row still carrying the old greeting regardless of what the rest of the
-- body says (own customisations included) rather than requiring an exact
-- match on wording that has had three revisions (101, 102, 103). Restricted
-- to the greeting's own fragment: `{{display_name}}` used anywhere else in a
-- customised body is left untouched, only the leading `{{display_name}},`
-- greeting line is replaced with `{{salutation}},`.
--
-- Unlike migration 212/224, zero matching rows here is a legitimate outcome
-- (every live tenant may already read migration 106's post-774 copy): there
-- is no known "expected" count to assert against, so this is a plain
-- self-healing UPDATE rather than a guarded-content DO block.

UPDATE notification_templates
   SET body_text = replace(COALESCE(body_text, ''), E'{{display_name}},\n\n', E'{{salutation}},\n\n'),
       body_html = replace(COALESCE(body_html, ''), '<p>{{display_name}},</p>', '<p>{{salutation}},</p>'),
       updated_at = NOW()
 WHERE event_type = 'forms.request_link'
   AND channel_type = 'email'
   AND (strpos(COALESCE(body_text, ''), E'{{display_name}},\n\n') > 0
        OR strpos(COALESCE(body_html, ''), '<p>{{display_name}},</p>') > 0);
