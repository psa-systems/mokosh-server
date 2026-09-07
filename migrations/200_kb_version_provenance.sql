-- PMS-1126: a KB version says what kind of change it was and why, and an
-- article says who last changed it.
--
-- `kb_article_versions` has carried `edited_by_id NOT NULL` since migration
-- 012, so every version already names its author and nothing here invents
-- attribution. What it lacked was the rest of the provenance: an optional
-- note the editor types on save ("why"), whether the row is the creation
-- snapshot, an edit or a restore, and for a restore which version it brought
-- back. `change_kind` is backfilled from the one fact the table holds
-- (`version_number = 1` is the snapshot `create_article` seeds; every later
-- row was an edit or a restore, and the two were indistinguishable before
-- this, so `edit` is the honest default).
--
-- `kb_articles.updated_by_id` records the last staff user who wrote the row
-- through any path (edit, restore, task toggle), including a metadata-only
-- edit that creates no version. It is deliberately NOT backfilled: the
-- reader falls back to the latest version's editor when it is NULL, which is
-- true for the rows that exist, and asserting more than that would be a
-- guess.

ALTER TABLE kb_article_versions
    ADD COLUMN change_note TEXT,
    ADD COLUMN change_kind VARCHAR(20) NOT NULL DEFAULT 'edit',
    ADD COLUMN restored_from_version INTEGER;

ALTER TABLE kb_article_versions
    ADD CONSTRAINT kb_article_versions_change_kind_check
        CHECK (change_kind IN ('create', 'edit', 'restore'));

UPDATE kb_article_versions SET change_kind = 'create' WHERE version_number = 1;

ALTER TABLE kb_articles
    ADD COLUMN updated_by_id UUID REFERENCES users(id) ON DELETE SET NULL;
