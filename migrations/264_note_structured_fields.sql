-- PMS-1359: structured fields on a technician note, alongside the free-text body.
--
-- Keeping AI out of the path is the point of this issue: a technician enters
-- the fields directly in the note form rather than having a model parse the
-- body. The design proposal (PMS-1359 2026-09-25) names four:
--
--   time_minutes   INTEGER       - billable or non-billable minutes the work took.
--                                  Unit matches `time_entries.duration_minutes` so a
--                                  note's time can seed a `time_entries` row without
--                                  conversion. NULL = not stated.
--   work_summary   VARCHAR(200)  - short handle for list views, distinct from the
--                                  long-form content.
--   parts_used     TEXT[]        - one string per part. NULL means "not applicable";
--                                  an empty array means "the field was answered no".
--   follow_up      JSONB         - { needed: bool, description: text|null,
--                                    target_date: date|null }. Two orthogonal
--                                    questions, kept together because they describe
--                                    one concept.
--
-- All four are nullable so every existing note stays valid without a backfill
-- (the immutability rule means one migration, not four).
--
-- Column form over a single jsonb blob so the reports the fields unlock
-- (SUM(time_minutes) per ticket / company / assignee, UNNEST(parts_used) +
-- COUNT, open-follow-ups filter) stay index-friendly. `follow_up` keeps a jsonb
-- shape because it is inherently two values that answer one question.

ALTER TABLE ticket_notes
    ADD COLUMN time_minutes INTEGER        CHECK (time_minutes IS NULL OR time_minutes > 0),
    ADD COLUMN work_summary VARCHAR(200),
    ADD COLUMN parts_used   TEXT[],
    ADD COLUMN follow_up    JSONB
        CHECK (
            follow_up IS NULL
            OR (follow_up ? 'needed' AND jsonb_typeof(follow_up -> 'needed') = 'boolean')
        );

COMMENT ON COLUMN ticket_notes.time_minutes IS
    'Minutes the work took, same unit as time_entries.duration_minutes (PMS-1359).';
COMMENT ON COLUMN ticket_notes.work_summary IS
    'Short label of what was done, for list views where the content is too long (PMS-1359).';
COMMENT ON COLUMN ticket_notes.parts_used IS
    'One string per part. NULL = not applicable, empty array = answered no (PMS-1359).';
COMMENT ON COLUMN ticket_notes.follow_up IS
    '{ needed: bool, description: text|null, target_date: date|null } (PMS-1359).';
