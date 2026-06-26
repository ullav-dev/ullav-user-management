CREATE TABLE user_ai_settings (
    username      TEXT PRIMARY KEY,
    provider      TEXT NOT NULL DEFAULT 'anthropic',
    model         TEXT NOT NULL DEFAULT 'claude-sonnet-4-6',
    encrypted_key TEXT,
    iv            TEXT,
    auth_tag      TEXT,
    ollama_url    TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
