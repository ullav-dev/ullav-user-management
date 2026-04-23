-- Permissions for ullav-collection-server
INSERT INTO permissions (name) VALUES
    ('objects:read'),
    ('objects:write'),
    ('objects:delete'),
    ('locations:read'),
    ('locations:write'),
    ('entries:read'),
    ('entries:write'),
    ('acquisitions:read'),
    ('acquisitions:write');

-- Seed three collection roles
INSERT INTO roles (name) VALUES
    ('collection_admin'),   -- full access to all collection operations
    ('curator'),            -- cataloguing, acquisitions, loans
    ('registrar');          -- entries, movements, condition checks (read-only on objects)

-- collection_admin: all collection permissions + health:read
INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
  WHERE r.name = 'collection_admin'
    AND p.name IN (
      'health:read',
      'objects:read', 'objects:write', 'objects:delete',
      'locations:read', 'locations:write',
      'entries:read', 'entries:write',
      'acquisitions:read', 'acquisitions:write'
    );

-- curator: objects + acquisitions (read/write), locations + entries read
INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
  WHERE r.name = 'curator'
    AND p.name IN (
      'objects:read', 'objects:write',
      'acquisitions:read', 'acquisitions:write',
      'locations:read',
      'entries:read'
    );

-- registrar: entries + locations (read/write), objects read-only
INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
  WHERE r.name = 'registrar'
    AND p.name IN (
      'objects:read',
      'locations:read', 'locations:write',
      'entries:read', 'entries:write'
    );

-- Grant all new permissions to the existing admin role
INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id
  FROM roles r CROSS JOIN permissions p
  WHERE r.name = 'admin'
    AND p.name IN (
      'objects:read', 'objects:write', 'objects:delete',
      'locations:read', 'locations:write',
      'entries:read', 'entries:write',
      'acquisitions:read', 'acquisitions:write'
    )
  ON CONFLICT DO NOTHING;
