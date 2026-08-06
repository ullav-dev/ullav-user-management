-- Flags one team per organization as "the Support team" — the team that owns
-- every ticket queue in a downstream ticketing app (currently cunav). Scoped
-- by organization_id (NULL = the default, org-less bucket every team lives in
-- today, since no app has adopted multi-tenancy yet except Tack) rather than
-- a single global flag, so this needs no further migration once other
-- services start running in the context of an Organization — see
-- 031_organizations.sql.
--
-- "At most one per organization_id" is enforced in application code
-- (admin_update_team: unset the old holder, then set the new one, inside one
-- transaction), the same pattern as oauth2_signing_keys.is_primary — see
-- 020_oauth2_key_rotation.sql — not a DB constraint, so the same NULLs-are-
-- distinct caveat that made a plain UNIQUE index unusable there applies here.

ALTER TABLE teams ADD COLUMN is_support_team BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_teams_support_team ON teams (organization_id)
    WHERE is_support_team = TRUE;
