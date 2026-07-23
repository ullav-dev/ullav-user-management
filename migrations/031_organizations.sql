-- Organizations: a new tenant boundary that owns Teams.
--
-- Fully additive and backward-compatible: `teams.organization_id` is nullable,
-- so every existing team and every existing app keeps working completely
-- unchanged. Tack (the new Notes & Pages content platform) is the first app
-- that actually requires organizations — it uses organization_id as its
-- Postgres shard key and as the audience boundary for organization-wide
-- content sharing. Other apps adopt organizations later, once proven, on
-- their own schedule.

CREATE TABLE organizations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    slug        TEXT        NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SET NULL (not CASCADE/RESTRICT) on delete — deleting an organization should
-- never delete or block-delete the teams that belonged to it; they simply
-- become org-less again, same as a team that was never assigned one.
ALTER TABLE teams ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

CREATE INDEX teams_organization_id_idx ON teams(organization_id);
