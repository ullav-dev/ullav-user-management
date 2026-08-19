-- Restricts a PAT to exactly one repo, rather than every repo the owning
-- user can access -- needed for lagan-server's GitHub Actions CI/CD engine
-- to mint an ephemeral, least-privilege credential per CI run (see
-- lagan-server/docs/github-actions-ci-plan.md section 4a: the design was
-- reviewed and approved before this migration was written).
--
-- No FK -- UUM doesn't own the `repos` table (lagan-server does); a bare
-- value-only cross-service reference, same pattern lagan-server's own
-- ci_awe_job_id/ci_template_workflow_id columns already use in the other
-- direction (a value referencing another service's row, resolved out of
-- band, not enforced by the database).
--
-- NULL (the existing/default case, and every PAT created before this
-- migration) means "every repo the user can access" -- unchanged behavior.
-- Non-NULL means "only this one repo" -- checked by lagan-server's
-- git_transport::permissions::can_read/can_write against the exchanged
-- JWT's git_repo_id claim, not by UUM itself (UUM has no notion of what a
-- repo even is).
ALTER TABLE personal_access_tokens
    ADD COLUMN IF NOT EXISTS repo_id UUID;
