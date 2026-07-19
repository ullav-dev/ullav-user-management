-- SSH public keys for git-over-SSH access (lagan).
--
-- `fingerprint` (OpenSSH's own "SHA256:<base64>" form, computed from the key
-- blob at insert time) is what an inbound SSH connection is keyed on — it lets
-- the SSH server resolve an offered key to a user in one indexed lookup
-- instead of re-parsing/re-hashing every stored key on every connection.
--
-- Scoped like a PAT (`scopes`) so a key added for read-only automation can't
-- push even if the owning account otherwise could.
CREATE TABLE IF NOT EXISTS user_ssh_keys (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    public_key   TEXT         NOT NULL,
    fingerprint  VARCHAR(128) NOT NULL UNIQUE,
    scopes       TEXT[]       NOT NULL DEFAULT ARRAY['repo:read', 'repo:write'],
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS user_ssh_keys_user_id_idx ON user_ssh_keys(user_id);
