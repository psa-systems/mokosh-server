-- Identity rows linking a Mokosh user to a third-party OAuth account.
-- Today only Google is wired up; the table is provider-agnostic so other
-- providers (Microsoft, GitHub, ...) can be added without a schema change.
--
-- Linking by the provider's stable subject (`sub` claim for Google) is
-- preferred over linking by email - if a user changes their Google email
-- we still recognize them via the subject.

CREATE TABLE user_oauth_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, subject)
);

CREATE INDEX user_oauth_identities_user_id_idx ON user_oauth_identities (user_id);
