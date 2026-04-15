-- Device-local per-conversation notification preferences.
--
-- A user can mute the same conversation on one device while leaving another
-- device unmuted. This table intentionally scopes the preference to
-- (user_id, device_id, conversation_id).

CREATE TABLE IF NOT EXISTS conversation_device_notification_prefs (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       INT NOT NULL,
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    muted           BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, conversation_id),
    FOREIGN KEY (user_id, device_id)
        REFERENCES user_devices(user_id, device_id)
        ON DELETE CASCADE,
    FOREIGN KEY (conversation_id, user_id)
        REFERENCES conversation_participants(conversation_id, user_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_conv_device_notification_prefs_conversation
    ON conversation_device_notification_prefs(conversation_id, user_id, device_id)
    WHERE muted = true;
