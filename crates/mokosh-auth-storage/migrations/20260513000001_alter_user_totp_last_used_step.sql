-- TOTP anti-replay: track the highest step we've ever verified for
-- this user so the SERIALIZABLE `consume_step` UPDATE can refuse to
-- accept the same step twice. NULL until the first successful verify.

ALTER TABLE mokosh_auth.user_totp
    ADD COLUMN last_used_step BIGINT;
