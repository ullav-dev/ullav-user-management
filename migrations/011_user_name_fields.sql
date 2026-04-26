-- Add optional first_name and last_name to the users table.
-- These are populated at registration time and returned on login
-- so the Clann webapp can create the user's initial Person record
-- with the correct name even when email verification happens on a
-- different device (where the in-browser clann_pending_tree key is absent).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS first_name TEXT,
    ADD COLUMN IF NOT EXISTS last_name  TEXT;
