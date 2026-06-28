-- OAuth2 DB-backed key rotation (Phase 2).
-- Signing keys are stored encrypted at rest with AES-256-GCM.
-- At most one row has is_primary = TRUE; that key is used to sign new tokens.
-- Retired keys are kept until all tokens they signed have expired (no tokens exceed 1 hour),
-- so retiring a key is safe after ~1 hour.
CREATE TABLE IF NOT EXISTS oauth2_signing_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kid         TEXT        NOT NULL UNIQUE,
    -- AES-256-GCM encrypted PKCS#8 PEM; decrypted with OAUTH2_KEY_ENCRYPTION_KEY at startup.
    key_pem_enc BYTEA       NOT NULL,
    nonce       BYTEA       NOT NULL,   -- 12-byte GCM nonce, unique per row
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ,            -- NULL = active; non-NULL = retired, kept for JWKS
    is_primary  BOOLEAN     NOT NULL DEFAULT FALSE
);

-- Only one key should be primary at a time; enforced by application logic.
CREATE INDEX IF NOT EXISTS idx_oauth2_signing_keys_primary ON oauth2_signing_keys (is_primary)
    WHERE is_primary = TRUE;
