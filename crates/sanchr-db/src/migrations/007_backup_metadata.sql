CREATE TABLE IF NOT EXISTS backup_objects (
    backup_id                            UUID PRIMARY KEY,
    owner_id                             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lineage_id                           UUID NOT NULL,
    format_version                       INTEGER NOT NULL,
    object_key                           TEXT NOT NULL UNIQUE,
    byte_size                            BIGINT NOT NULL,
    sha256_hash                          TEXT NOT NULL,
    opaque_metadata                      BYTEA NOT NULL,
    reserved_forward_secrecy_metadata    BYTEA NOT NULL DEFAULT ''::bytea,
    is_committed                         BOOLEAN NOT NULL DEFAULT false,
    created_at                           TIMESTAMPTZ NOT NULL DEFAULT now(),
    committed_at                         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_backup_objects_owner_created
    ON backup_objects(owner_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_backup_objects_owner_lineage
    ON backup_objects(owner_id, lineage_id);
