-- Tack (Notes & Pages content platform) product and access control.
--
-- Tack follows the team-granted pattern shared by Obair, Togra, Cunav,
-- Cartlann, and Lagan: an admin enables the product for a team, and team
-- members then have access.

INSERT INTO products (slug, name, description)
VALUES ('tack', 'Tack', 'Notes & Pages content platform')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO permissions (name) VALUES ('tack:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'tack:manage'
ON CONFLICT DO NOTHING;
