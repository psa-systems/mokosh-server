-- The "your admin disabled MFA on your account" banner needs a signal
-- on the user row. Set by `TotpRepository::disenroll` (either path),
-- cleared by `TotpRepository::confirm` on a fresh re-enrollment. NULL
-- = no banner.

ALTER TABLE mokosh_auth.users
    ADD COLUMN mfa_disenrolled_at TIMESTAMPTZ;
