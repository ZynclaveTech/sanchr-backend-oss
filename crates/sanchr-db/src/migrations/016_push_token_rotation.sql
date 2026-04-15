-- Sub-phase 6: Push Token Rotation
--
-- Track when a push token was last rotated per device. A static, long-lived
-- APNs/FCM token is a stable identifier that can be used to track a user
-- across services. The iOS client requests a fresh token from APNs every
-- 7 days; this column timestamps the most recent rotation for audit and
-- for enforcing the rotation policy server-side if needed.

ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS push_token_rotated_at TIMESTAMPTZ;
