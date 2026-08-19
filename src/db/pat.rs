use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{AdminPatSummary, PatSummary},
};

fn row_to_summary(row: &tokio_postgres::Row) -> PatSummary {
    PatSummary {
        id: row.get("id"),
        name: row.get("name"),
        token_prefix: row.get("token_prefix"),
        scopes: row.get("scopes"),
        expires_at: row.get("expires_at"),
        last_used_at: row.get("last_used_at"),
        created_at: row.get("created_at"),
        revoked_at: row.get("revoked_at"),
    }
}

/// Create a new PAT row. Only the hash is stored — the raw token is returned
/// to the caller once by the handler and never persisted.
pub async fn create_pat(
    pool: &Pool,
    user_id: Uuid,
    name: &str,
    token_hash: &str,
    token_prefix: &str,
    scopes: &[String],
    expires_in_days: Option<i64>,
) -> Result<PatSummary, AppError> {
    let expires_at = expires_in_days.map(|d| Utc::now() + Duration::days(d));
    let conn = pool.get().await?;
    let row = conn
        .query_one(
            "INSERT INTO personal_access_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, name, token_prefix, scopes, expires_at, last_used_at, created_at, revoked_at",
            &[&user_id, &name, &token_hash, &token_prefix, &scopes, &expires_at],
        )
        .await
        .map_err(|e| {
            if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                AppError::Conflict
            } else {
                AppError::Database(e)
            }
        })?;
    Ok(row_to_summary(&row))
}

/// List a user's own PATs, newest first. Includes revoked tokens (with
/// `revoked_at` set) so the owner can see their own history.
pub async fn list_pats(pool: &Pool, user_id: Uuid) -> Result<Vec<PatSummary>, AppError> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT id, name, token_prefix, scopes, expires_at, last_used_at, created_at, revoked_at
             FROM personal_access_tokens
             WHERE user_id = $1
             ORDER BY created_at DESC",
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_summary).collect())
}

/// Revoke a PAT. Ownership-scoped: only the owning user may revoke their own
/// token. Returns `AppError::NotFound` if it doesn't exist, isn't theirs, or
/// is already revoked.
pub async fn revoke_pat(pool: &Pool, user_id: Uuid, id: Uuid) -> Result<(), AppError> {
    let conn = pool.get().await?;
    let n = conn
        .execute(
            "UPDATE personal_access_tokens SET revoked_at = NOW()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
            &[&id, &user_id],
        )
        .await?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// A PAT resolved by hash — the shape `handlers::pat::exchange` needs to mint
/// a `GitAccessClaims` token for the owning user.
#[derive(Debug)]
pub struct ResolvedPat {
    pub id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    /// `Some` restricts the exchanged JWT's `git_repo_id` claim to this one
    /// repo (see `migrations/033_pat_repo_scope.sql`) — `None` for every
    /// PAT created before that migration, and every user-created PAT since
    /// (only `create_ephemeral_pat` below ever sets it).
    pub repo_id: Option<Uuid>,
}

/// Look up an active (non-revoked, non-expired) PAT by its SHA-256 hash.
/// Returns `AppError::InvalidToken` if not found or inactive — deliberately
/// the same error as any other bad credential, so a git client can't
/// distinguish "wrong token" from "revoked token" from "unknown token".
pub async fn get_active_pat_by_hash(pool: &Pool, token_hash: &str) -> Result<ResolvedPat, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT id, user_id, scopes, repo_id FROM personal_access_tokens
             WHERE token_hash = $1
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > NOW())",
            &[&token_hash],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;
    Ok(ResolvedPat {
        id: row.get(0),
        user_id: row.get(1),
        scopes: row.get(2),
        repo_id: row.get(3),
    })
}

/// Creates a server-minted, repo-scoped PAT — used by
/// `handlers::pat::mint_ephemeral` to give a CI run exactly the read access
/// its triggering push's author already has to *one* repo, nothing broader.
/// Unlike `create_pat`, the caller supplies `expires_at` directly (a short,
/// bounded TTL in seconds/minutes, not the user-facing `expires_in_days`)
/// and there's no `name` to display in a UI — this token is never listed via
/// `GET /pat` for the user to manage by hand, only revocable the same way
/// any PAT is (`DELETE /pat/{id}`, or simply letting it expire).
pub async fn create_ephemeral_pat(
    pool: &Pool,
    user_id: Uuid,
    repo_id: Uuid,
    token_hash: &str,
    token_prefix: &str,
    scopes: &[String],
    expires_at: DateTime<Utc>,
) -> Result<Uuid, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_one(
            "INSERT INTO personal_access_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at, repo_id)
             VALUES ($1, 'CI (ephemeral)', $2, $3, $4, $5, $6)
             RETURNING id",
            &[&user_id, &token_hash, &token_prefix, &scopes, &expires_at, &repo_id],
        )
        .await
        .map_err(|e| {
            if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                AppError::Conflict
            } else {
                AppError::Database(e)
            }
        })?;
    Ok(row.get(0))
}

/// Update `last_used_at` for a PAT. Best-effort — failures are logged, not
/// propagated, since this must never block the git operation it's tracking.
pub async fn touch_pat_last_used(pool: &Pool, id: Uuid) {
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => { log::warn!("touch_pat_last_used: pool error: {e}"); return; }
    };
    if let Err(e) = conn
        .execute(
            "UPDATE personal_access_tokens SET last_used_at = NOW() WHERE id = $1",
            &[&id],
        )
        .await
    {
        log::warn!("touch_pat_last_used: update failed: {e}");
    }
}

/// Admin audit view: every PAT across every user (never the raw token/hash).
pub async fn admin_list_all_pats(pool: &Pool) -> Result<Vec<AdminPatSummary>, AppError> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT p.id, p.user_id, u.username, p.name, p.token_prefix, p.scopes,
                    p.expires_at, p.last_used_at, p.created_at, p.revoked_at
             FROM personal_access_tokens p
             JOIN users u ON u.id = p.user_id
             ORDER BY p.created_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| AdminPatSummary {
            id: row.get(0),
            user_id: row.get(1),
            username: row.get(2),
            name: row.get(3),
            token_prefix: row.get(4),
            scopes: row.get(5),
            expires_at: row.get::<_, Option<DateTime<Utc>>>(6),
            last_used_at: row.get(7),
            created_at: row.get(8),
            revoked_at: row.get(9),
        })
        .collect())
}
