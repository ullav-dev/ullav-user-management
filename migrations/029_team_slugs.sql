-- Team slugs — human-readable identifiers used by lagan's git clone URLs
-- (`{team-slug}/{repo-slug}.git`) instead of raw team UUIDs. `teams.name`
-- has no uniqueness constraint (see migrations/012_teams.sql), so existing
-- rows are backfilled here with collision-safe slugs before the column is
-- made NOT NULL + UNIQUE.

ALTER TABLE teams ADD COLUMN IF NOT EXISTS slug VARCHAR(255);

-- Backfill: lowercase name, replace runs of non-alphanumerics with a single
-- hyphen, trim leading/trailing hyphens. Empty results (e.g. a name that's
-- entirely punctuation) fall back to the team's short id so the column can
-- still be made NOT NULL.
UPDATE teams
SET slug = NULLIF(
    trim(both '-' from regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g')),
    ''
)
WHERE slug IS NULL;

UPDATE teams
SET slug = 'team-' || substr(id::text, 1, 8)
WHERE slug IS NULL;

-- De-duplicate collisions deterministically by created_at (oldest keeps the
-- bare slug; later teams get -2, -3, ... appended), since name uniqueness
-- was never enforced.
WITH ranked AS (
    SELECT id, slug,
           row_number() OVER (PARTITION BY slug ORDER BY created_at, id) AS rn
    FROM teams
)
UPDATE teams t
SET slug = t.slug || '-' || ranked.rn
FROM ranked
WHERE t.id = ranked.id AND ranked.rn > 1;

ALTER TABLE teams ALTER COLUMN slug SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS teams_slug_idx ON teams(slug);
