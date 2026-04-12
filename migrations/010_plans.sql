-- Plans: available subscription plans per product.
-- Each product defines its own set of named plan slugs.
-- Existing subscriptions retain their plan slug string regardless of what plans exist here.

CREATE TABLE IF NOT EXISTS plans (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID        NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    slug       TEXT        NOT NULL,
    name       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (product_id, slug)
);

-- Seed plans for clann
INSERT INTO plans (product_id, slug, name)
SELECT p.id, v.slug, v.name
FROM products p
CROSS JOIN (VALUES
    ('individual',   'Individual'),
    ('family',       'Family'),
    ('professional', 'Professional'),
    ('enterprise',   'Enterprise')
) AS v(slug, name)
WHERE p.slug = 'clann'
ON CONFLICT DO NOTHING;

-- Seed plans for comad
INSERT INTO plans (product_id, slug, name)
SELECT p.id, v.slug, v.name
FROM products p
CROSS JOIN (VALUES
    ('individual', 'Individual'),
    ('team',       'Team'),
    ('enterprise', 'Enterprise')
) AS v(slug, name)
WHERE p.slug = 'comad'
ON CONFLICT DO NOTHING;
