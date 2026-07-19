use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{AdminSshKeySummary, SshKeySummary},
};

fn row_to_summary(row: &tokio_postgres::Row) -> SshKeySummary {
    SshKeySummary {
        id: row.get("id"),
        name: row.get("name"),
        fingerprint: row.get("fingerprint"),
        scopes: row.get("scopes"),
        created_at: row.get("created_at"),
        last_used_at: row.get("last_used_at"),
    }
}

/// Register a new SSH public key for a user. `fingerprint` is computed by the
/// caller (`handlers::ssh_keys` — parses/validates the OpenSSH key line and
/// derives the `SHA256:...` fingerprint) so this module stays pure DB access.
pub async fn create_ssh_key(
    pool: &Pool,
    user_id: Uuid,
    name: &str,
    public_key: &str,
    fingerprint: &str,
    scopes: &[String],
) -> Result<SshKeySummary, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_one(
            "INSERT INTO user_ssh_keys (user_id, name, public_key, fingerprint, scopes)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, name, fingerprint, scopes, created_at, last_used_at",
            &[&user_id, &name, &public_key, &fingerprint, &scopes],
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

/// List a user's own SSH keys, newest first.
pub async fn list_ssh_keys(pool: &Pool, user_id: Uuid) -> Result<Vec<SshKeySummary>, AppError> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT id, name, fingerprint, scopes, created_at, last_used_at
             FROM user_ssh_keys
             WHERE user_id = $1
             ORDER BY created_at DESC",
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_summary).collect())
}

/// Delete an SSH key. Ownership-scoped: only the owning user may remove their
/// own key. Returns `AppError::NotFound` if it doesn't exist or isn't theirs.
pub async fn delete_ssh_key(pool: &Pool, user_id: Uuid, id: Uuid) -> Result<(), AppError> {
    let conn = pool.get().await?;
    let n = conn
        .execute(
            "DELETE FROM user_ssh_keys WHERE id = $1 AND user_id = $2",
            &[&id, &user_id],
        )
        .await?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// A key resolved by fingerprint — the shape `handlers::ssh_keys::resolve`
/// needs to mint a `GitAccessClaims` token for the owning user.
#[derive(Debug)]
pub struct ResolvedSshKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
}

/// Look up a key by its `SHA256:...` fingerprint. Returns
/// `AppError::InvalidToken` (not `NotFound`) if unmatched — same rationale as
/// `pat::get_active_pat_by_hash`: don't let a caller distinguish "no such key"
/// from any other auth failure.
pub async fn get_ssh_key_by_fingerprint(pool: &Pool, fingerprint: &str) -> Result<ResolvedSshKey, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT id, user_id, scopes FROM user_ssh_keys WHERE fingerprint = $1",
            &[&fingerprint],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;
    Ok(ResolvedSshKey {
        id: row.get(0),
        user_id: row.get(1),
        scopes: row.get(2),
    })
}

/// Update `last_used_at` for an SSH key. Best-effort, same rationale as
/// `pat::touch_pat_last_used`.
pub async fn touch_ssh_key_last_used(pool: &Pool, id: Uuid) {
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => { log::warn!("touch_ssh_key_last_used: pool error: {e}"); return; }
    };
    if let Err(e) = conn
        .execute(
            "UPDATE user_ssh_keys SET last_used_at = NOW() WHERE id = $1",
            &[&id],
        )
        .await
    {
        log::warn!("touch_ssh_key_last_used: update failed: {e}");
    }
}

/// Admin audit view: every SSH key across every user.
pub async fn admin_list_all_ssh_keys(pool: &Pool) -> Result<Vec<AdminSshKeySummary>, AppError> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT k.id, k.user_id, u.username, k.name, k.fingerprint, k.scopes,
                    k.created_at, k.last_used_at
             FROM user_ssh_keys k
             JOIN users u ON u.id = k.user_id
             ORDER BY k.created_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| AdminSshKeySummary {
            id: row.get(0),
            user_id: row.get(1),
            username: row.get(2),
            name: row.get(3),
            fingerprint: row.get(4),
            scopes: row.get(5),
            created_at: row.get(6),
            last_used_at: row.get(7),
        })
        .collect())
}
