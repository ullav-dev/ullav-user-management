use crate::errors::AppError;
use crate::models::{PasswordResetToken, User};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

/// Insert a new user into the database, returning the full row.
pub async fn create_user(
    pool: &Pool,
    email: &str,
    username: &str,
    password_hash: &str,
) -> Result<User, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "INSERT INTO users (email, username, password_hash, is_active)
             VALUES ($1, $2, $3, FALSE)
             RETURNING id, email, username, password_hash, is_active, created_at, updated_at,
                       confirmation_token, confirmation_token_expires_at",
            &[&email, &username, &password_hash],
        )
        .await
        .map_err(|e| {
            // PostgreSQL unique-violation code is 23505
            if let Some(db_err) = e.as_db_error() {
                if db_err.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                    return AppError::Conflict;
                }
            }
            AppError::Database(e)
        })?;

    Ok(row_to_user(&row))
}

/// Fetch a user by their UUID.
pub async fn get_user_by_id(pool: &Pool, id: Uuid) -> Result<User, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, email, username, password_hash, is_active, created_at, updated_at,
                    confirmation_token, confirmation_token_expires_at
             FROM users WHERE id = $1",
            &[&id],
        )
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(row_to_user(&row))
}

/// Fetch a user by their email address.
pub async fn get_user_by_email(pool: &Pool, email: &str) -> Result<User, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, email, username, password_hash, is_active, created_at, updated_at,
                    confirmation_token, confirmation_token_expires_at
             FROM users WHERE email = $1",
            &[&email],
        )
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(row_to_user(&row))
}

/// Update a user's password hash.
pub async fn update_password(
    pool: &Pool,
    user_id: Uuid,
    new_hash: &str,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
            &[&new_hash, &user_id],
        )
        .await?;

    if updated == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Create a password-reset token valid for `ttl_minutes` minutes.
pub async fn create_reset_token(
    pool: &Pool,
    user_id: Uuid,
    token: &str,
    ttl_minutes: i64,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let expires_at = Utc::now() + Duration::minutes(ttl_minutes);
    client
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at)
             VALUES ($1, $2, $3)",
            &[&user_id, &token, &expires_at],
        )
        .await?;
    Ok(())
}

/// Look up a password-reset token row.
pub async fn get_reset_token(
    pool: &Pool,
    token: &str,
) -> Result<PasswordResetToken, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, user_id, token, expires_at, used, created_at
             FROM password_reset_tokens
             WHERE token = $1",
            &[&token],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;

    Ok(PasswordResetToken {
        id: row.get("id"),
        user_id: row.get("user_id"),
        token: row.get("token"),
        expires_at: row.get("expires_at"),
        used: row.get("used"),
        created_at: row.get("created_at"),
    })
}

/// Mark a password-reset token as used.
pub async fn consume_reset_token(pool: &Pool, token: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE token = $1",
            &[&token],
        )
        .await?;
    Ok(())
}

/// Store an email-confirmation token on the user row.
pub async fn set_confirmation_token(
    pool: &Pool,
    user_id: Uuid,
    token: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE users
             SET confirmation_token = $1, confirmation_token_expires_at = $2
             WHERE id = $3",
            &[&token, &expires_at, &user_id],
        )
        .await?;
    Ok(())
}

/// Look up a user by their email-confirmation token.
pub async fn get_user_by_confirmation_token(
    pool: &Pool,
    token: &str,
) -> Result<User, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, email, username, password_hash, is_active, created_at, updated_at,
                    confirmation_token, confirmation_token_expires_at
             FROM users WHERE confirmation_token = $1",
            &[&token],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;

    Ok(row_to_user(&row))
}

/// Activate a user and clear their confirmation token columns.
pub async fn activate_user(pool: &Pool, user_id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE users
             SET is_active = TRUE,
                 confirmation_token = NULL,
                 confirmation_token_expires_at = NULL,
                 updated_at = NOW()
             WHERE id = $1",
            &[&user_id],
        )
        .await?;
    Ok(())
}

/// Fetch all role names and permission names for a user.
///
/// Returns `(roles, permissions)` as sorted, deduplicated vecs.
pub async fn get_user_roles_and_permissions(
    pool: &Pool,
    user_id: Uuid,
) -> Result<(Vec<String>, Vec<String>), AppError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT r.name AS role_name, p.name AS permission_name
             FROM user_roles ur
             JOIN roles r ON r.id = ur.role_id
             LEFT JOIN role_permissions rp ON rp.role_id = r.id
             LEFT JOIN permissions p ON p.id = rp.permission_id
             WHERE ur.user_id = $1",
            &[&user_id],
        )
        .await?;

    let mut roles = std::collections::HashSet::new();
    let mut permissions = std::collections::HashSet::new();

    for row in &rows {
        let role_name: String = row.get("role_name");
        let permission_name: Option<String> = row.get("permission_name");
        roles.insert(role_name);
        if let Some(perm) = permission_name {
            permissions.insert(perm);
        }
    }

    let mut roles: Vec<String> = roles.into_iter().collect();
    let mut permissions: Vec<String> = permissions.into_iter().collect();
    roles.sort();
    permissions.sort();

    Ok((roles, permissions))
}

/// Assign a named role to a user (no-op if already assigned).
pub async fn assign_role(pool: &Pool, user_id: Uuid, role_name: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO user_roles (user_id, role_id)
             SELECT $1, id FROM roles WHERE name = $2
             ON CONFLICT DO NOTHING",
            &[&user_id, &role_name],
        )
        .await?;
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn row_to_user(row: &tokio_postgres::Row) -> User {
    User {
        id: row.get("id"),
        email: row.get("email"),
        username: row.get("username"),
        password_hash: row.get("password_hash"),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        confirmation_token: row.get("confirmation_token"),
        confirmation_token_expires_at: row.get("confirmation_token_expires_at"),
    }
}
