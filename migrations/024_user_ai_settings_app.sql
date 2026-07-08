-- user_ai_settings was keyed by username only, making it a single row shared by
-- every app that calls this endpoint (currently Togra). Add an `app` column so
-- each app gets its own isolated row instead of silently overwriting /
-- corrupting (via mismatched encryption keys) another app's settings.
--
-- Existing rows predate this column and were written by Togra, the only caller
-- until now — backfill them to 'togra' so Togra keeps working with no client
-- changes (it doesn't send an `app` param; the handler defaults to 'togra').

ALTER TABLE user_ai_settings ADD COLUMN IF NOT EXISTS app TEXT NOT NULL DEFAULT 'togra';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'user_ai_settings_pkey'
    ) THEN
        ALTER TABLE user_ai_settings DROP CONSTRAINT user_ai_settings_pkey;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'user_ai_settings_pkey'
    ) THEN
        ALTER TABLE user_ai_settings ADD CONSTRAINT user_ai_settings_pkey PRIMARY KEY (username, app);
    END IF;
END $$;
