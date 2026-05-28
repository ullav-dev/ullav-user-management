-- Add optional avatar URL to the users table.
-- Downstream apps resolve display avatars from this URL (Gravatar or a CDN upload).
-- Stored as a URL string; blob storage and dimension enforcement belong in the DAM service.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar_url TEXT;
