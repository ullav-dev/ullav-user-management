-- Obair (AWE — Advanced Workflow Engine) product and team-scoped access tables.
--
-- Obair access is not subscription-based: an admin grants a team access to
-- the product, and the team owner then assigns per-member product roles.
-- This pattern is generalised so future products can reuse the same tables.

-- Seed the Obair product (no plans table entry — access is team-granted, not subscribed).
INSERT INTO products (slug, name, description)
VALUES ('obair', 'Obair', 'Advanced Workflow Engine')
ON CONFLICT (slug) DO NOTHING;

-- Which teams have access to which products.
-- Populated by admins; cascades away if the team is deleted.
CREATE TABLE team_product_access (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      UUID        NOT NULL REFERENCES teams(id)    ON DELETE CASCADE,
    product_slug TEXT        NOT NULL REFERENCES products(slug) ON DELETE RESTRICT,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(team_id, product_slug)
);

CREATE INDEX team_product_access_team_id_idx ON team_product_access(team_id);

-- Per-member access level for a product within an enabled team.
--
-- Valid role values per product:
--   obair  → 'admin' | 'lead' | 'member'
--
-- The FK to team_product_access ensures a member role cannot exist unless
-- the team has the product enabled; revoking team access cascades away all
-- member roles for that product automatically.
-- The FK to team_members ensures the user is an actual member of the team.
CREATE TABLE team_member_product_roles (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      UUID        NOT NULL REFERENCES teams(id)    ON DELETE CASCADE,
    user_id      UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    product_slug TEXT        NOT NULL REFERENCES products(slug) ON DELETE RESTRICT,
    role         TEXT        NOT NULL,
    assigned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(team_id, user_id, product_slug),
    FOREIGN KEY (team_id, user_id)      REFERENCES team_members(team_id, user_id)           ON DELETE CASCADE,
    FOREIGN KEY (team_id, product_slug) REFERENCES team_product_access(team_id, product_slug) ON DELETE CASCADE
);

CREATE INDEX team_member_product_roles_team_id_idx ON team_member_product_roles(team_id);
CREATE INDEX team_member_product_roles_user_id_idx ON team_member_product_roles(user_id);

-- Permission for admins to enable/disable product access for teams.
INSERT INTO permissions (name) VALUES ('obair:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'obair:manage'
ON CONFLICT DO NOTHING;
