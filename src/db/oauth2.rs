use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use uuid::Uuid;

use crate::errors::AppError;

// ── Client ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OAuth2Client {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub first_party: bool,
}

pub async fn get_oauth2_client(pool: &Pool, client_id: &str) -> Result<OAuth2Client, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT client_id, client_name, redirect_uris, allowed_scopes, first_party
             FROM oauth2_clients WHERE client_id = $1",
            &[&client_id],
        )
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(OAuth2Client {
        client_id:     row.get(0),
        client_name:   row.get(1),
        redirect_uris: row.get(2),
        allowed_scopes: row.get(3),
        first_party:   row.get(4),
    })
}

pub async fn register_oauth2_client(
    pool: &Pool,
    client_id: &str,
    client_name: &str,
    redirect_uris: &[String],
    allowed_scopes: &[String],
    registered_by: Option<Uuid>,
) -> Result<OAuth2Client, AppError> {
    let conn = pool.get().await?;
    conn.execute(
        "INSERT INTO oauth2_clients (client_id, client_name, redirect_uris, allowed_scopes, registered_by)
         VALUES ($1, $2, $3, $4, $5)",
        &[&client_id, &client_name, &redirect_uris, &allowed_scopes, &registered_by],
    )
    .await
    .map_err(|e| {
        if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
            AppError::Conflict
        } else {
            AppError::Database(e)
        }
    })?;
    Ok(OAuth2Client {
        client_id: client_id.to_owned(),
        client_name: client_name.to_owned(),
        redirect_uris: redirect_uris.to_vec(),
        allowed_scopes: allowed_scopes.to_vec(),
        first_party: false,
    })
}

// ── Auth codes ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AuthCode {
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub resource: String,
    pub code_challenge: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn create_auth_code(
    pool: &Pool,
    code: &str,
    client_id: &str,
    user_id: Uuid,
    redirect_uri: &str,
    scope: &str,
    resource: &str,
    code_challenge: &str,
    ttl_minutes: i64,
) -> Result<(), AppError> {
    let expires_at = Utc::now() + Duration::minutes(ttl_minutes);
    let conn = pool.get().await?;
    conn.execute(
        "INSERT INTO oauth2_auth_codes
         (code, client_id, user_id, redirect_uri, scope, resource, code_challenge, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[&code, &client_id, &user_id, &redirect_uri, &scope, &resource, &code_challenge, &expires_at],
    )
    .await?;
    Ok(())
}

/// Atomically mark the auth code as used and return it.
///
/// Returns `AppError::InvalidToken` if the code does not exist, has already been
/// used, or has expired.
pub async fn consume_auth_code(pool: &Pool, code: &str) -> Result<AuthCode, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "UPDATE oauth2_auth_codes
             SET used_at = NOW()
             WHERE code = $1
               AND used_at IS NULL
               AND expires_at > NOW()
             RETURNING client_id, user_id, redirect_uri, scope, resource, code_challenge, expires_at",
            &[&code],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;
    Ok(AuthCode {
        client_id:      row.get(0),
        user_id:        row.get(1),
        redirect_uri:   row.get(2),
        scope:          row.get(3),
        resource:       row.get(4),
        code_challenge: row.get(5),
        expires_at:     row.get(6),
    })
}

// ── Refresh tokens ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RefreshToken {
    pub client_id: String,
    pub user_id: Uuid,
    pub scope: String,
    pub resource: String,
}

pub async fn create_refresh_token(
    pool: &Pool,
    token_hash: &str,
    client_id: &str,
    user_id: Uuid,
    scope: &str,
    resource: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    let expires_at = Utc::now() + Duration::days(ttl_days);
    let conn = pool.get().await?;
    conn.execute(
        "INSERT INTO oauth2_refresh_tokens (token_hash, client_id, user_id, scope, resource, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[&token_hash, &client_id, &user_id, &scope, &resource, &expires_at],
    )
    .await?;
    Ok(())
}

/// Rotate a refresh token: mark the old one as rotated and return its data.
///
/// Returns `AppError::InvalidToken` if not found, already rotated, or expired.
pub async fn rotate_refresh_token(pool: &Pool, token_hash: &str) -> Result<RefreshToken, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "UPDATE oauth2_refresh_tokens
             SET rotated_at = NOW()
             WHERE token_hash = $1
               AND rotated_at IS NULL
               AND expires_at > NOW()
             RETURNING client_id, user_id, scope, resource",
            &[&token_hash],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;
    Ok(RefreshToken {
        client_id: row.get(0),
        user_id:   row.get(1),
        scope:     row.get(2),
        resource:  row.get(3),
    })
}

pub async fn revoke_refresh_token(pool: &Pool, token_hash: &str) -> Result<(), AppError> {
    let conn = pool.get().await?;
    conn.execute(
        "UPDATE oauth2_refresh_tokens SET rotated_at = NOW()
         WHERE token_hash = $1 AND rotated_at IS NULL",
        &[&token_hash],
    )
    .await?;
    Ok(())
}

// ── User sessions (SSO cookie) ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct UserSession {
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

pub async fn create_user_session(
    pool: &Pool,
    token_hash: &str,
    user_id: Uuid,
    ttl_days: i64,
) -> Result<(), AppError> {
    let expires_at = Utc::now() + Duration::days(ttl_days);
    let conn = pool.get().await?;
    conn.execute(
        "INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        &[&token_hash, &user_id, &expires_at],
    )
    .await?;
    Ok(())
}

pub async fn get_user_session(pool: &Pool, token_hash: &str) -> Result<UserSession, AppError> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT user_id, expires_at FROM user_sessions
             WHERE token_hash = $1 AND expires_at > NOW()",
            &[&token_hash],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;
    Ok(UserSession {
        user_id:    row.get(0),
        expires_at: row.get(1),
    })
}

pub async fn delete_user_session(pool: &Pool, token_hash: &str) -> Result<(), AppError> {
    let conn = pool.get().await?;
    conn.execute("DELETE FROM user_sessions WHERE token_hash = $1", &[&token_hash])
        .await?;
    Ok(())
}

// ── Signing key store ─────────────────────────────────────────────────────────

/// A signing key row as returned from the DB (encrypted material + metadata).
pub struct SigningKeyRow {
    pub kid:         String,
    pub key_pem_enc: Vec<u8>,
    pub nonce:       Vec<u8>,
    pub is_primary:  bool,
}

/// Load all active (non-retired) signing keys ordered newest-first.
pub async fn load_active_signing_keys(pool: &Pool) -> Result<Vec<SigningKeyRow>, AppError> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT kid, key_pem_enc, nonce, is_primary
             FROM oauth2_signing_keys
             WHERE retired_at IS NULL
             ORDER BY created_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| SigningKeyRow {
            kid:         r.get(0),
            key_pem_enc: r.get::<_, Vec<u8>>(1),
            nonce:       r.get::<_, Vec<u8>>(2),
            is_primary:  r.get(3),
        })
        .collect())
}

/// Persist a new signing key (encrypted). The new key will NOT be primary until
/// `promote_signing_key` is called.
pub async fn store_signing_key(
    pool:        &Pool,
    kid:         &str,
    key_pem_enc: &[u8],
    nonce:       &[u8],
    make_primary: bool,
) -> Result<(), AppError> {
    let conn = pool.get().await?;
    if make_primary {
        // Demote any existing primary first.
        conn.execute(
            "UPDATE oauth2_signing_keys SET is_primary = FALSE WHERE is_primary = TRUE",
            &[],
        )
        .await?;
    }
    conn.execute(
        "INSERT INTO oauth2_signing_keys (kid, key_pem_enc, nonce, is_primary)
         VALUES ($1, $2, $3, $4)",
        &[&kid, &key_pem_enc, &nonce, &make_primary],
    )
    .await?;
    Ok(())
}

/// Promote an existing key to primary, demoting the current one.
pub async fn promote_signing_key(pool: &Pool, kid: &str) -> Result<(), AppError> {
    let conn = pool.get().await?;
    conn.execute(
        "UPDATE oauth2_signing_keys SET is_primary = FALSE WHERE is_primary = TRUE",
        &[],
    )
    .await?;
    let n = conn
        .execute(
            "UPDATE oauth2_signing_keys SET is_primary = TRUE WHERE kid = $1",
            &[&kid],
        )
        .await?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Mark a key as retired. Retired keys remain in JWKS until all tokens they signed expire.
pub async fn retire_signing_key(pool: &Pool, kid: &str) -> Result<(), AppError> {
    let conn = pool.get().await?;
    let n = conn
        .execute(
            "UPDATE oauth2_signing_keys SET retired_at = NOW(), is_primary = FALSE
             WHERE kid = $1 AND retired_at IS NULL",
            &[&kid],
        )
        .await?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Key metadata returned by the admin list endpoint (includes retired keys).
#[derive(Debug, Serialize)]
pub struct SigningKeyInfo {
    pub kid:        String,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

/// Return metadata for ALL signing keys (active and retired), ordered newest-first.
pub async fn list_all_signing_keys(pool: &Pool) -> Result<Vec<SigningKeyInfo>, AppError> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT kid, is_primary, created_at, retired_at
             FROM oauth2_signing_keys
             ORDER BY created_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| SigningKeyInfo {
            kid:        r.get(0),
            is_primary: r.get(1),
            created_at: r.get(2),
            retired_at: r.get(3),
        })
        .collect())
}

// ── Audit log ─────────────────────────────────────────────────────────────────

/// Write a single audit log entry. Failures are logged but not propagated —
/// audit logging must not block the main flow.
pub async fn audit_log(
    pool:       &Pool,
    event_type: &str,
    user_id:    Option<Uuid>,
    client_id:  Option<&str>,
    scope:      Option<&str>,
    resource:   Option<&str>,
    ip_address: Option<&str>,
    error:      Option<&str>,
) {
    let conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => { log::warn!("audit_log: pool error: {e}"); return; }
    };
    if let Err(e) = conn.execute(
        "INSERT INTO oauth2_audit_log
            (event_type, user_id, client_id, scope, resource, ip_address, error)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[&event_type, &user_id, &client_id, &scope, &resource, &ip_address, &error],
    ).await {
        log::warn!("audit_log: insert failed: {e}");
    }
}
