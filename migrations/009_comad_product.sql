-- Seed the Comad digital asset management product.
INSERT INTO products (slug, name, description)
VALUES ('comad', 'Comad', 'Digital asset management platform')
ON CONFLICT (slug) DO NOTHING;
