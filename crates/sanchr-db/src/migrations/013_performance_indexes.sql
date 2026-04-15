CREATE INDEX IF NOT EXISTS idx_backup_objects_owner_committed
    ON backup_objects(owner_id, committed_at DESC NULLS LAST, created_at DESC)
    WHERE is_committed = true;

CREATE INDEX IF NOT EXISTS idx_conversations_updated_at_id
    ON conversations(updated_at DESC, id);

CREATE INDEX IF NOT EXISTS idx_conv_participants_user_conversation
    ON conversation_participants(user_id, conversation_id);
