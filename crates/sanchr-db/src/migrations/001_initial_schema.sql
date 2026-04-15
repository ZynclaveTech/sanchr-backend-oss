CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_number    TEXT UNIQUE NOT NULL,
    phone_hash      BYTEA NOT NULL,
    display_name    TEXT NOT NULL,
    email           TEXT,
    password_hash   TEXT NOT NULL,
    avatar_url      TEXT,
    status_text     TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    is_active       BOOLEAN DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_users_phone_hash ON users(phone_hash);

CREATE TABLE IF NOT EXISTS user_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       INT NOT NULL,
    device_name     TEXT,
    platform        TEXT NOT NULL,
    push_token      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at  TIMESTAMPTZ,
    UNIQUE(user_id, device_id)
);

CREATE TABLE IF NOT EXISTS user_settings (
    user_id                 UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    read_receipts           BOOLEAN DEFAULT true,
    online_status_visible   BOOLEAN DEFAULT true,
    typing_indicator        BOOLEAN DEFAULT true,
    profile_photo_visibility TEXT DEFAULT 'everyone',
    sanchr_mode_enabled       BOOLEAN DEFAULT false,
    screen_lock_enabled     BOOLEAN DEFAULT false,
    screen_lock_timeout     INT DEFAULT 60,
    screenshot_protection   BOOLEAN DEFAULT false,
    biometric_lock          BOOLEAN DEFAULT false,
    message_notifications   BOOLEAN DEFAULT true,
    group_notifications     BOOLEAN DEFAULT true,
    call_notifications      BOOLEAN DEFAULT true,
    notification_sound      TEXT DEFAULT 'default',
    notification_vibrate    BOOLEAN DEFAULT true,
    show_preview            BOOLEAN DEFAULT true,
    theme                   TEXT DEFAULT 'light',
    font_size               TEXT DEFAULT 'medium',
    chat_wallpaper          TEXT,
    auto_download_wifi      TEXT DEFAULT 'photos,videos,documents',
    auto_download_mobile    TEXT DEFAULT 'photos',
    auto_download_roaming   TEXT DEFAULT 'none',
    low_data_mode           BOOLEAN DEFAULT false,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
