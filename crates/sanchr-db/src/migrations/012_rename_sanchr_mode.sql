DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_settings'
          AND column_name = 'vync_mode_enabled'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_settings'
          AND column_name = 'sanchr_mode_enabled'
    ) THEN
        ALTER TABLE user_settings
            RENAME COLUMN vync_mode_enabled TO sanchr_mode_enabled;
    END IF;
END
$$;
