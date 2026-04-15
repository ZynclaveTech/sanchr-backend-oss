CREATE TABLE IF NOT EXISTS identity_keys (
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           INT NOT NULL,
    identity_public_key BYTEA NOT NULL,
    registered_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS signed_pre_keys (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       INT NOT NULL,
    key_id          INT NOT NULL,
    public_key      BYTEA NOT NULL,
    signature       BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, key_id)
);

CREATE TABLE IF NOT EXISTS one_time_pre_keys (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       INT NOT NULL,
    key_id          INT NOT NULL,
    public_key      BYTEA NOT NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, key_id)
);
