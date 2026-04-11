-- Add permissions for admin user-management endpoints.
INSERT INTO permissions (name) VALUES ('users:read'), ('users:write')
ON CONFLICT DO NOTHING;

-- Grant both to the admin role.
INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
  WHERE r.name = 'admin'
    AND p.name IN ('users:read', 'users:write')
ON CONFLICT DO NOTHING;
