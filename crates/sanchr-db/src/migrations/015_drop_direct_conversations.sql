-- Sub-phase 4: Opaque Conversation IDs
--
-- Drop the direct_conversations pair-index table. This table stored a sorted
-- (user_a, user_b) → conversation_id mapping that constituted an explicit
-- social-graph index: any party with DB read access could trivially enumerate
-- all 1:1 relationships by scanning a single table.
--
-- Conversation IDs have always been randomly generated UUIDs (gen_random_uuid())
-- so they never revealed participants on their own. The pair-index was purely an
-- optimisation; the canonical participant data lives in conversation_participants,
-- which is the sole source of truth going forward.
--
-- find_or_create_direct() now uses a participants self-join protected by a
-- transient pg_advisory_xact_lock (not persisted) for race-free creation.

DROP TABLE IF EXISTS direct_conversations;
