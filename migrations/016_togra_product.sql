-- Togra (project planning tool) product and access control.
--
-- Togra access follows the same team-granted pattern as Obair:
-- an admin enables the product for a team, and team members then have access.
-- Previously Togra piggybacked on the obair gate; this migration gives it
-- its own slug so access can be managed independently.

INSERT INTO products (slug, name, description)
VALUES ('togra', 'Togra', 'Project planning tool')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO permissions (name) VALUES ('togra:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'togra:manage'
ON CONFLICT DO NOTHING;
