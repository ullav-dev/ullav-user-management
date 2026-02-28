ALTER TABLE users
  ADD COLUMN confirmation_token          TEXT,
  ADD COLUMN confirmation_token_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_confirmation_token
  ON users (confirmation_token);
