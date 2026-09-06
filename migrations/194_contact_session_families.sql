-- PMS-1062: a contact session belongs to a rotation family.
--
-- `POST /api/v1/contact/auth/refresh` rotates a refresh token by
-- revoking the presented row and minting a new one, and before this
-- the new row carried no link to the old. Presenting an already
-- rotated token (the stolen-token signal: the honest customer rotated
-- it, and now somebody else holds the copy) was a 401 for that token
-- only, while the token it was rotated into kept rotating. The
-- retired portal treated the replay as theft and revoked the whole
-- chain, so the customer and the thief were both signed out.
--
-- `family_id` is the id of the first session in the chain (a login
-- or a magic-link redeem) and every rotation copies it forward, so
-- "the whole chain" is one UPDATE by family rather than a recursive
-- walk. Existing rows each become their own family: every one of
-- them was the head of a chain nothing could follow.
ALTER TABLE contact_sessions ADD COLUMN family_id UUID;
UPDATE contact_sessions SET family_id = id;
ALTER TABLE contact_sessions ALTER COLUMN family_id SET NOT NULL;

CREATE INDEX idx_contact_sessions_family
    ON contact_sessions (family_id)
    WHERE revoked_at IS NULL;
