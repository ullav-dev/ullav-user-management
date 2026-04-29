-- Teams feature: introduces teams and team_members tables.
-- Also seeds the teams:create permission and grants it to the admin role.

CREATE TYPE team_member_status AS ENUM ('invited', 'active', 'inactive');

CREATE TABLE teams (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    purpose     TEXT,
    avatar_url  VARCHAR(512),
    owner_id    UUID         NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    leader_id   UUID         NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX teams_owner_id_idx  ON teams(owner_id);
CREATE INDEX teams_leader_id_idx ON teams(leader_id);

CREATE TABLE team_members (
    id                      UUID               PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                 UUID               NOT NULL REFERENCES teams(id)  ON DELETE CASCADE,
    user_id                 UUID               NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    status                  team_member_status NOT NULL DEFAULT 'invited',
    invited_by              UUID               REFERENCES users(id) ON DELETE SET NULL,
    invite_token            VARCHAR(128)       UNIQUE,
    invite_token_expires_at TIMESTAMPTZ,
    invited_at              TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    joined_at               TIMESTAMPTZ,
    UNIQUE(team_id, user_id)
);

CREATE INDEX team_members_team_id_idx ON team_members(team_id);
CREATE INDEX team_members_user_id_idx ON team_members(user_id);
CREATE INDEX team_members_token_idx   ON team_members(invite_token) WHERE invite_token IS NOT NULL;

-- teams:create is gated — not granted to the default 'user' role
INSERT INTO permissions (name) VALUES ('teams:create') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'teams:create'
ON CONFLICT DO NOTHING;
