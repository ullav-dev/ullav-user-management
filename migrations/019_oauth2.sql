-- OAuth2 Authorization Server tables
-- Implements RFC 6749, RFC 7591 (DCR), RFC 7636 (PKCE), RFC 8707 (resource indicators)

CREATE TABLE IF NOT EXISTS oauth2_clients (
    client_id          TEXT        PRIMARY KEY,
    client_name        TEXT        NOT NULL,
    redirect_uris      TEXT[]      NOT NULL,
    allowed_scopes     TEXT[]      NOT NULL DEFAULT '{}',
    -- TRUE for first-party clients (Claude Desktop, Claude Code) — skip consent screen.
    first_party        BOOLEAN     NOT NULL DEFAULT FALSE,
    registered_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL for publicly-registered (DCR) clients.
    registered_by      UUID        REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS oauth2_auth_codes (
    code               TEXT        PRIMARY KEY,
    client_id          TEXT        NOT NULL REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri       TEXT        NOT NULL,
    scope              TEXT        NOT NULL,
    -- The canonical URI of the target resource server (RFC 8707 resource indicator).
    resource           TEXT        NOT NULL,
    -- PKCE S256 code challenge (base64url-encoded SHA-256 of the verifier).
    code_challenge     TEXT        NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    -- Populated when the code is exchanged; prevents replay.
    used_at            TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth2_auth_codes_client_id_idx ON oauth2_auth_codes(client_id);
CREATE INDEX IF NOT EXISTS oauth2_auth_codes_expires_at_idx ON oauth2_auth_codes(expires_at);

CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
    -- SHA-256 hash of the raw token (prevents plaintext storage).
    token_hash         TEXT        PRIMARY KEY,
    client_id          TEXT        NOT NULL REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope              TEXT        NOT NULL,
    resource           TEXT        NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    -- Populated on rotation; used tokens are kept for 24 h for replay detection.
    rotated_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth2_refresh_tokens_user_id_idx ON oauth2_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS oauth2_refresh_tokens_expires_at_idx ON oauth2_refresh_tokens(expires_at);

-- Browser sessions — set as HttpOnly cookie so the OAuth2 authorize endpoint
-- can offer one-click consent for already-logged-in users without re-authentication.
CREATE TABLE IF NOT EXISTS user_sessions (
    -- SHA-256 hash of the raw session token.
    token_hash         TEXT        PRIMARY KEY,
    user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_sessions_user_id_idx ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS user_sessions_expires_at_idx ON user_sessions(expires_at);

-- Pre-register first-party Anthropic Claude clients.
-- Redirect URIs use the loopback scheme (RFC 8252 §7.3): port is ignored during validation.
INSERT INTO oauth2_clients (client_id, client_name, redirect_uris, allowed_scopes, first_party)
VALUES
    ('claude-desktop',
     'Claude Desktop',
     ARRAY['http://localhost/callback'],
     ARRAY['mcp:tools'],
     TRUE),
    ('claude-code',
     'Claude Code CLI',
     ARRAY['http://localhost/callback'],
     ARRAY['mcp:tools'],
     TRUE)
ON CONFLICT (client_id) DO NOTHING;
