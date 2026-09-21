-- PMS-1295: the timestamp of the newest Bunyip event applied to a grant row.
-- The webhook upsert only accepts an event strictly newer than this, so a
-- late or replayed event never overwrites newer state.
ALTER TABLE mokosh_bunyip_grants ADD COLUMN event_at TIMESTAMPTZ;
UPDATE mokosh_bunyip_grants SET event_at = COALESCE(revoked_at, granted_at);
ALTER TABLE mokosh_bunyip_grants ALTER COLUMN event_at SET NOT NULL;
ALTER TABLE mokosh_bunyip_grants ALTER COLUMN event_at SET DEFAULT NOW();
