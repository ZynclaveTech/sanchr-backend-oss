CREATE TABLE IF NOT EXISTS direct_conversations (
    user_a UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_a, user_b),
    UNIQUE (conversation_id),
    CHECK (user_a < user_b)
);

CREATE INDEX IF NOT EXISTS idx_direct_conversations_user_a ON direct_conversations(user_a);
CREATE INDEX IF NOT EXISTS idx_direct_conversations_user_b ON direct_conversations(user_b);
