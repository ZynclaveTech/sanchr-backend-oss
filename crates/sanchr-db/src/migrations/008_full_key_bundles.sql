ALTER TABLE identity_keys
    ADD COLUMN IF NOT EXISTS registration_id INT;

ALTER TABLE signed_pre_keys
    ADD COLUMN IF NOT EXISTS timestamp_ms BIGINT;

CREATE TABLE IF NOT EXISTS kyber_pre_keys (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       INT NOT NULL,
    key_id          INT NOT NULL,
    public_key      BYTEA NOT NULL,
    signature       BYTEA NOT NULL,
    timestamp_ms    BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, key_id)
);
