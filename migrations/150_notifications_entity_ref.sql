-- Per-entity notification metadata.
--
-- The portal inbox previously carried the rendered subject / body only,
-- so a "New ticket comment" row could not click through to the actual
-- ticket. Adds two nullable columns:
--
-- - entity_type: 'ticket' / 'invoice' / 'quote' / 'kb_article' / etc.
--   Free-form so a new template can carry a new entity kind without a
--   schema change.
-- - entity_id: the target row id. Nullable because auth / system
--   notifications ('auth.welcome', 'auth.password_reset') do not
--   attach to a single tenant row.
--
-- The dispatcher reads `entity_type` + `entity_id` from the render
-- context (`context.entity_type`, `context.entity_id`) and stamps
-- them on every notification row it inserts. The portal read path
-- (`PortalNotification` in `src/modules/portal/models.rs`) surfaces
-- the pair so the SPA can render an entity-level deep-link on the
-- inbox.
--
-- No index yet: the notifications table is already indexed on
-- (tenant_id, user_id) and (tenant_id, contact_id), and the new
-- columns are read only on the per-row inbox render, not on any
-- WHERE clause today.

ALTER TABLE notifications
    ADD COLUMN entity_type VARCHAR(50),
    ADD COLUMN entity_id UUID;
