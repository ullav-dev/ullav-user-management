-- OAuth2 audit log — records token issuances, revocations, and failed attempts.
-- Immutable (no UPDATE or DELETE expected); append-only insert from UUM.
CREATE TABLE IF NOT EXISTS oauth2_audit_log (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   TEXT        NOT NULL,   -- 'token_issued', 'token_revoked', 'auth_failed', 'register'
    user_id      UUID        REFERENCES users(id),
    client_id    TEXT,
    scope        TEXT,
    ip_address   TEXT,
    resource     TEXT,                   -- audience / resource server URI
    error        TEXT,                   -- set for failed events
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth2_audit_log_user    ON oauth2_audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_audit_log_client  ON oauth2_audit_log (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_audit_log_created ON oauth2_audit_log (created_at);
