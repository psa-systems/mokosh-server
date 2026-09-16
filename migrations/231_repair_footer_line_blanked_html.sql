-- PMS-1237 finding 5: repair `body_html` rows migration 212 blanked.
--
-- Migration 212's UPDATE matched a row when EITHER its `body_text` carried
-- the old footer sentence OR its `body_html` did:
--
--   WHERE strpos(COALESCE(body_text, ''), text_fragment) > 0
--      OR strpos(COALESCE(body_html, ''), html_fragment) > 0
--
-- but its SET clause rewrote BOTH columns unconditionally through
-- `COALESCE(column, '')`:
--
--   SET body_text = replace(COALESCE(body_text, ''), text_fragment, ...),
--       body_html = replace(COALESCE(body_html, ''), html_fragment, ...)
--
-- A row whose `body_text` matched but whose `body_html` was NULL (a
-- text-only template: no HTML alternative for that channel) took the
-- `COALESCE(body_html, '') -> ''` branch, found no `html_fragment` to
-- replace in an empty string, and committed `body_html = ''` where it had
-- been NULL. `NotificationTemplateResponse.body_html` and
-- `render_event`/`update_template` all treat "no HTML part" as `NULL`
-- (`match template.body_html.as_deref() { Some(_) => render, None => no
-- html row }`), so this converted "no HTML alternative" into "an HTML
-- alternative that is a blank document", which the mailer sends as the
-- multipart HTML part instead of omitting it: a blank HTML email for a
-- template that was never authored with one.
--
-- Migration 212 is immutable (it already ran), so this repairs the data
-- rather than editing that file. The set of affected rows is identifiable
-- without ambiguity: `body_html = ''` is not a value `update_template`
-- (`UpsertNotificationTemplateRequest.body_html: Option<String>`) or any
-- seed migration ever writes on purpose (an absent HTML part is always
-- `NULL`, never an empty string), and every one of 212's own seeded/rewritten
-- bodies contains far more than the footer alone, so the ONLY way its
-- `replace()` could produce an empty result is starting from `COALESCE(NULL,
-- '')`. A row is repaired only when its `body_text` shows it was touched by
-- 212 (carries the composed `{{msp_footer_line}}` key) and its `body_html`
-- is the empty string 212's bug can produce.

UPDATE notification_templates
   SET body_html = NULL,
       updated_at = NOW()
 WHERE body_html = ''
   AND strpos(COALESCE(body_text, ''), '{{msp_footer_line}}') > 0;
