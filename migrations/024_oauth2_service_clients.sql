-- OAuth2 client_credentials grant support — confidential "service" clients for
-- unattended (machine-to-machine) callers, e.g. AWE automated tasks calling a
-- first-party MCP server without a human present to complete an interactive
-- authorization_code login.
--
-- A service client is bound to a dedicated service-account `users` row (its
-- token's `sub`), so minted tokens flow through the exact same identity/claims
-- pipeline (`build_identity_claims`, product entitlement checks) as a human
-- user's token — no special-casing needed anywhere downstream.

ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS client_secret_hash TEXT;
ALTER TABLE oauth2_clients ADD COLUMN IF NOT EXISTS service_account_user_id UUID
    REFERENCES users(id) ON DELETE CASCADE;

-- `oauth2:manage` gates `/admin/oauth2/*` (key rotation + the service-client
-- endpoints added above) in src/main.rs, but no prior migration ever granted
-- it to any role — those endpoints have been unreachable by anyone, in any
-- environment, since they were added. Same seed pattern as every other
-- `$product:manage` permission (see migrations 014/016/017/022/023).
INSERT INTO permissions (name) VALUES ('oauth2:manage') ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name = 'oauth2:manage'
ON CONFLICT DO NOTHING;
