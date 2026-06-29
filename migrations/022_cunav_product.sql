-- Cunav (support ticketing) product and access control.
--
-- Cunav follows the team-granted pattern shared by Obair, Togra, and Cartlann:
-- an admin enables the product for a team and assigns the "support" product role
-- to team members who should have cross-team ticket visibility.
-- Any authenticated user may file a ticket without being a Cunav team member;
-- the product gate only applies to the Cunav MCP endpoint.

INSERT INTO products (slug, name, description)
VALUES ('cunav', 'Cunav', 'Support ticketing platform')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO permissions (name) VALUES ('cunav:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'cunav:manage'
ON CONFLICT DO NOTHING;
