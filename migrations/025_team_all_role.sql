-- Seed a built-in "All" team role for every existing team (new teams get this via
-- application code in db::create_team) and assign it to all currently-active members.
--
-- The role is identified structurally via is_all, not by its (renameable) name, so
-- owners can rename it freely without breaking the auto-assign/delete-protection logic.
-- It cannot be deleted and is always kept in sync with active membership (enforced in
-- application code — see db::assign_all_role_to_member, db::delete_team_role,
-- db::unassign_member_role).

ALTER TABLE team_roles ADD COLUMN is_all BOOLEAN NOT NULL DEFAULT false;

-- At most one "All" role per team.
CREATE UNIQUE INDEX team_roles_one_all_per_team_idx ON team_roles(team_id) WHERE is_all;

-- Adopt any pre-existing role literally named 'All' as the built-in one, instead of
-- inserting a fresh row — inserting would collide with it on UNIQUE(team_id, name).
UPDATE team_roles SET is_all = true WHERE name = 'All';

-- Seed only for teams that still lack an is_all role.
INSERT INTO team_roles (team_id, name, description, is_all)
SELECT t.id, 'All', 'Everybody in the team', true
FROM teams t
WHERE NOT EXISTS (
    SELECT 1 FROM team_roles tr WHERE tr.team_id = t.id AND tr.is_all
);

INSERT INTO team_member_roles (team_id, role_id, member_id)
SELECT tm.team_id, tr.id, tm.id
FROM team_members tm
JOIN team_roles tr ON tr.team_id = tm.team_id AND tr.is_all
WHERE tm.status = 'active'
ON CONFLICT DO NOTHING;
