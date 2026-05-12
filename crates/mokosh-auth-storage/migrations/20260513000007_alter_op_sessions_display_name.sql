-- Optional user-friendly label for a session row, e.g. "Work laptop",
-- "Phone". Set via /v1/auth/sessions/{id}/rename. NULL until the user
-- renames it; the Sessions UI falls back to UA parsing.

ALTER TABLE mokosh_auth.op_sessions
    ADD COLUMN display_name TEXT;
