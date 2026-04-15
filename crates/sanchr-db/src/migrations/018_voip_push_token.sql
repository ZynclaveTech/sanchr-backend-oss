-- Add VoIP push token column for PushKit (iOS only).
-- Separate from the regular APNs push_token because PushKit issues its own
-- device token via PKPushRegistry; it's not the same as the alert push token.
ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS voip_push_token TEXT;

CREATE INDEX IF NOT EXISTS idx_user_devices_voip_push_token
    ON user_devices (voip_push_token)
    WHERE voip_push_token IS NOT NULL;
