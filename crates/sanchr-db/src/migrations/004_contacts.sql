CREATE TABLE IF NOT EXISTS contacts (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name    TEXT,
    is_blocked      BOOLEAN DEFAULT false,
    is_favorite     BOOLEAN DEFAULT false,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, contact_user_id)
);

CREATE INDEX IF NOT EXISTS idx_contacts_user_id ON contacts(user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_blocked ON contacts(user_id, is_blocked) WHERE is_blocked = true;
