-- PMS-729 phase 2 §7 slice B / I12: portal notifications inbox.
--
-- The `notifications` table (migration 013) hangs off `user_id`; portal
-- identities are a `contacts` row, not a `users` row, so a portal
-- customer had no way to persist a notification against themselves. This
-- migration adds an optional `contact_id` column so the dispatcher can
-- fan out to a contact-authored recipient and the portal inbox has
-- something durable to read.
--
-- Nullable + `ON DELETE CASCADE` so removing a contact drops their
-- inbox (matches the `user_id` behaviour); at insert time either
-- `user_id` OR `contact_id` (or neither, for the pure recipient-email
-- rows the dispatcher already writes) is populated. No constraint
-- enforces mutual exclusivity: an agent-visible event could reasonably
-- fan out to BOTH a user and a copied contact.
--
-- Partial index keyed on `(contact_id, read_at) WHERE contact_id IS NOT
-- NULL AND read_at IS NULL` matches the existing `user_id` unread hot
-- path so the portal inbox counter stays cheap even for a chatty
-- tenant.

ALTER TABLE notifications
    ADD COLUMN contact_id UUID REFERENCES contacts(id) ON DELETE CASCADE;

CREATE INDEX idx_notifications_contact
    ON notifications(contact_id)
    WHERE contact_id IS NOT NULL;

CREATE INDEX idx_notifications_contact_unread
    ON notifications(contact_id, read_at)
    WHERE contact_id IS NOT NULL AND read_at IS NULL;

COMMENT ON COLUMN notifications.contact_id IS
    'PMS-729 phase 2 §7 slice B: portal recipient identity. Set when the dispatcher fans out to a `contacts` row (via a `recipient_contact_id` context key or a rule with `contacts` in its recipients JSONB).';
