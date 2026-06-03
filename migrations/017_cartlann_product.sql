-- Cartlann (collection management) product and access control.
--
-- Cartlann access follows the team-granted pattern shared by Obair and Togra:
-- an admin enables the product for a team, and team members get per-member
-- product roles (admin | curator | registrar | viewer).

INSERT INTO products (slug, name, description)
VALUES ('cartlann', 'Cartlann', 'Collection management platform')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO permissions (name) VALUES ('cartlann:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'cartlann:manage'
ON CONFLICT DO NOTHING;
