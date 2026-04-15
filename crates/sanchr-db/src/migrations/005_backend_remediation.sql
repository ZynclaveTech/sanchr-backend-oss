ALTER TABLE users
    ADD COLUMN IF NOT EXISTS phone_verified_at TIMESTAMPTZ;

UPDATE users
SET phone_verified_at = created_at
WHERE phone_verified_at IS NULL;

ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS installation_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_installation
    ON user_devices(user_id, installation_id)
    WHERE installation_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS pending_registrations (
    phone_number    TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    email           TEXT,
    password_hash   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_registrations_expires_at
    ON pending_registrations(expires_at);

CREATE TABLE IF NOT EXISTS media_objects (
    media_id        UUID PRIMARY KEY,
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose         TEXT NOT NULL,
    storage_key     TEXT NOT NULL UNIQUE,
    content_type    TEXT NOT NULL,
    file_size       BIGINT NOT NULL,
    sha256_hash     TEXT NOT NULL,
    is_confirmed    BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_media_objects_owner_id
    ON media_objects(owner_id);
