-- PMS-591: soft-delete timestamp for users tombstoned via the Bunyip
-- `account_deleted` webhook. NULL when the user is live; a non-NULL value
-- tombstones the row without cascading through FK-owned history
-- (time_entries, audit_log, contracts, ...), which the compliance posture
-- requires we retain. Auth lookups (`get_user_by_id`,
-- `find_user_placement`) filter on `deleted_at IS NULL` so a tombstoned
-- user cannot authenticate through either the legacy HS256 path or the
-- bunyip-RS path even if a stale cookie / bearer arrives.

ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ NULL DEFAULT NULL;

-- Partial index over live users: every hot-path auth lookup filters on
-- `deleted_at IS NULL`, so a partial index keeps the working set tight
-- (the index carries only live rows) without inflating the tombstone
-- write path.
CREATE INDEX idx_users_live ON users(id) WHERE deleted_at IS NULL;
