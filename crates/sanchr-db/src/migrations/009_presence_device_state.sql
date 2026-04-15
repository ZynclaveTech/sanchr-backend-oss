ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS last_presence_state TEXT NOT NULL DEFAULT 'offline';

ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS last_presence_changed_at TIMESTAMPTZ;

UPDATE user_devices
SET last_presence_changed_at = COALESCE(last_presence_changed_at, last_active_at, now())
WHERE last_presence_changed_at IS NULL;
