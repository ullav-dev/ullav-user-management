-- Team roles: custom labels defined per-team, consumed by downstream services
-- (DAM, AWE, etc.) to gate functionality. Not linked to the global RBAC
-- permissions table — downstream services interpret role names themselves.

CREATE TABLE team_roles (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID         NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE(team_id, name),
    -- Needed so team_member_roles can use a composite FK guaranteeing
    -- that a role and the member it is assigned to belong to the same team.
    UNIQUE(id, team_id)
);

CREATE INDEX team_roles_team_id_idx ON team_roles(team_id);

-- Add composite unique constraint to team_members for the same FK trick.
ALTER TABLE team_members
    ADD CONSTRAINT team_members_id_team_id_key UNIQUE (id, team_id);

-- Junction: which team_roles each team_member holds.
-- Composite FKs ensure at DB level that role and member belong to the same team.
CREATE TABLE team_member_roles (
    team_id     UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    role_id     UUID        NOT NULL,
    member_id   UUID        NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, member_id),
    FOREIGN KEY (role_id,   team_id) REFERENCES team_roles(id,   team_id) ON DELETE CASCADE,
    FOREIGN KEY (member_id, team_id) REFERENCES team_members(id, team_id) ON DELETE CASCADE
);

CREATE INDEX team_member_roles_member_id_idx ON team_member_roles(member_id);
CREATE INDEX team_member_roles_team_id_idx   ON team_member_roles(team_id);
