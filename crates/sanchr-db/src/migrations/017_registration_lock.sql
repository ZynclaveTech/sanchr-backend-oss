-- Registration Lock: adds per-user PIN-based re-registration protection.
--
-- registration_lock_enabled: whether the lock is active for this account.
-- registration_lock_pin_hash: Argon2id PHC string of the user's PIN.
--   NULL when the lock is disabled. The plaintext PIN never leaves the client
--   over anything other than TLS; the hash is the only server-side secret.

ALTER TABLE user_settings
    ADD COLUMN IF NOT EXISTS registration_lock_enabled  BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS registration_lock_pin_hash TEXT;
