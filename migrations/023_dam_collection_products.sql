-- DAM (Comad) and Collection Management MCP products.
--
-- These follow the same team-granted pattern as Obair and Cunav.
-- An admin enables the product for a team; the product gate is enforced
-- at the /mcp endpoint of each respective server.

INSERT INTO products (slug, name, description)
VALUES ('comad', 'Comad', 'Digital Asset Management')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO products (slug, name, description)
VALUES ('collection', 'Collection', 'Collection Management')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO permissions (name) VALUES ('comad:manage')     ON CONFLICT DO NOTHING;
INSERT INTO permissions (name) VALUES ('collection:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'comad:manage'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'collection:manage'
ON CONFLICT DO NOTHING;
