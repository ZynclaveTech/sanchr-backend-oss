-- Add per-token expiry to refresh_tokens.
--
-- Previously the table had no expiry column, so tokens were only invalidated
-- by explicit revocation or rotation. This migration adds `expires_at` so the
-- validate query can enforce a hard TTL (default: 90 days from creation).

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL
        DEFAULT (now() + INTERVAL '90 days');

-- Backfill rows that were just given the default: anchor expiry to the
-- original created_at so pre-existing tokens don't get an accidental 90-day
-- extension from the time the migration runs.
UPDATE refresh_tokens
    SET expires_at = created_at + INTERVAL '90 days'
    WHERE expires_at > now() + INTERVAL '89 days 23 hours';

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens (expires_at);
