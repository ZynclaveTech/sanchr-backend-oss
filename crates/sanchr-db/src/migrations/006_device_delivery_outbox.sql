ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS supports_delivery_ack BOOLEAN NOT NULL DEFAULT false;
