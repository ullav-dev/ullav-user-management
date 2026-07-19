-- Lagan (git hosting / code review) product and access control.
--
-- Follows the team-granted pattern shared by Obair, Togra, Cunav, and
-- Cartlann: an admin enables the product for a team, and repos are owned by
-- teams (`lagan-server`'s own `repos.owner_team_id`). A user can read/write a
-- repo only via membership in a team that both (a) has `lagan` enabled here
-- and (b) owns or was granted access to that specific repo — the product
-- gate controls "can this team use lagan at all", repo-level visibility and
-- team-role checks (in lagan-server) control access to a specific repo.

INSERT INTO products (slug, name, description)
VALUES ('lagan', 'Lagan', 'Git hosting, pull requests, and code review')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO permissions (name) VALUES ('lagan:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'lagan:manage'
ON CONFLICT DO NOTHING;
