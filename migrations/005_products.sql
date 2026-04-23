-- Products registry — one row per Ullav product that supports subscriptions.
-- All downstream subscription rows reference this table.

CREATE TABLE IF NOT EXISTS products (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed known products (idempotent).
INSERT INTO products (slug, name, description)
VALUES
    ('clann', 'Clann Family Tree',    'Family tree and genealogy platform')
ON CONFLICT (slug) DO NOTHING;
