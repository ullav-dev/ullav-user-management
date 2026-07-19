-- Personal access tokens (PATs) — user-issued, long-lived credentials for
-- git-over-HTTPS Basic auth (lagan) and other non-interactive CLI use.
--
-- Modeled on user_sessions (opaque random token, SHA-256 hash at rest,
-- looked up by hash) rather than oauth2_clients: there is no OAuth2 client
-- app in this flow, the user is both the "client" and the resource owner.
--
-- Scoped like an OAuth2 grant (`scopes`) so a token minted for read-only git
-- access cannot be used to push even if the owning account otherwise could.
CREATE TABLE IF NOT EXISTS personal_access_tokens (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    token_hash   TEXT         NOT NULL UNIQUE,
    -- First chars of the raw token (e.g. "lgn_pat_a1b2c3"), shown in the UI
    -- after creation so a user can tell tokens apart without re-displaying
    -- the secret value.
    token_prefix VARCHAR(16)  NOT NULL,
    scopes       TEXT[]       NOT NULL DEFAULT ARRAY['repo:read', 'repo:write'],
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS personal_access_tokens_user_id_idx ON personal_access_tokens(user_id);

-- Gates the admin audit endpoints (list all PATs / SSH keys across users).
-- Every user manages their *own* tokens/keys via /pat and /ssh-keys with no
-- permission beyond being authenticated — this permission is audit-only.
INSERT INTO permissions (name) VALUES ('git_credentials:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'git_credentials:manage'
ON CONFLICT DO NOTHING;
