use crate::errors::AppError;
use crate::models::{
    AdminSubscription, PasswordResetToken, PlanResponse, ProductResponse, RoleWithPermissions,
    Subscription, SubscriptionsPage, User, UserWithRoles, UsersPage,
};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

/// Insert a new user into the database, returning the full row.
pub async fn create_user(
    pool: &Pool,
    email: &str,
    username: &str,
    password_hash: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
) -> Result<User, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "INSERT INTO users (email, username, password_hash, is_active, first_name, last_name)
             VALUES ($1, $2, $3, FALSE, $4, $5)
             RETURNING id, email, username, password_hash, is_active, first_name, last_name,
                       created_at, updated_at, confirmation_token, confirmation_token_expires_at",
            &[&email, &username, &password_hash, &first_name, &last_name],
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
            "SELECT id, email, username, password_hash, is_active, first_name, last_name,
                    created_at, updated_at, confirmation_token, confirmation_token_expires_at
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
            "SELECT id, email, username, password_hash, is_active, first_name, last_name,
                    created_at, updated_at, confirmation_token, confirmation_token_expires_at
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
            "SELECT id, email, username, password_hash, is_active, first_name, last_name,
                    created_at, updated_at, confirmation_token, confirmation_token_expires_at
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

// ── Subscriptions ────────────────────────────────────────────────────────────

/// Fetch the active/trialing subscription for a user and product slug.
///
/// Returns `None` when the user has no subscription for that product
/// (callers should treat this as an Individual/free tier).
pub async fn get_subscription(
    pool: &Pool,
    user_id: Uuid,
    product_slug: &str,
) -> Result<Option<Subscription>, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT s.id, s.user_id, s.product_id, p.slug AS product_slug,
                    s.plan, s.status, s.payment_provider,
                    s.provider_subscription_id, s.provider_customer_id,
                    s.seat_count, s.trial_end,
                    s.current_period_start, s.current_period_end,
                    s.created_at, s.updated_at
             FROM subscriptions s
             JOIN products p ON p.id = s.product_id
             WHERE s.user_id = $1
               AND p.slug    = $2
               AND s.status IN ('active','trialing','past_due')
             LIMIT 1",
            &[&user_id, &product_slug],
        )
        .await?;

    Ok(row.as_ref().map(row_to_subscription))
}

/// Fetch all active/trialing subscriptions for a user across all products.
///
/// Called at login to populate the `subscriptions` JWT claim.
pub async fn get_all_user_subscriptions(
    pool: &Pool,
    user_id: Uuid,
) -> Result<Vec<Subscription>, AppError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT s.id, s.user_id, s.product_id, p.slug AS product_slug,
                    s.plan, s.status, s.payment_provider,
                    s.provider_subscription_id, s.provider_customer_id,
                    s.seat_count, s.trial_end,
                    s.current_period_start, s.current_period_end,
                    s.created_at, s.updated_at
             FROM subscriptions s
             JOIN products p ON p.id = s.product_id
             WHERE s.user_id = $1
               AND s.status IN ('active','trialing','past_due')",
            &[&user_id],
        )
        .await?;

    Ok(rows.iter().map(row_to_subscription).collect())
}

/// Upsert a subscription row by provider subscription ID.
///
/// Used by Stripe and PayPal webhook handlers to keep the subscription
/// table in sync with the payment provider's state (Phase 3).
#[allow(dead_code)]
pub async fn upsert_subscription_by_provider_id(
    pool: &Pool,
    provider_subscription_id: &str,
    plan: &str,
    status: &str,
    seat_count: i16,
    trial_end: Option<DateTime<Utc>>,
    current_period_start: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE subscriptions
             SET plan                  = $2,
                 status                = $3,
                 seat_count            = $4,
                 trial_end             = $5,
                 current_period_start  = $6,
                 current_period_end    = $7,
                 updated_at            = NOW()
             WHERE provider_subscription_id = $1",
            &[
                &provider_subscription_id,
                &plan,
                &status,
                &seat_count,
                &trial_end,
                &current_period_start,
                &current_period_end,
            ],
        )
        .await?;
    Ok(())
}

/// Activate a new subscription after a successful checkout session (Phase 3).
#[allow(dead_code)]
pub async fn activate_subscription(
    pool: &Pool,
    user_id: Uuid,
    product_slug: &str,
    plan: &str,
    payment_provider: &str,
    provider_subscription_id: &str,
    provider_customer_id: &str,
    seat_count: i16,
    trial_end: Option<DateTime<Utc>>,
    current_period_start: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
) -> Result<Subscription, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "INSERT INTO subscriptions
                (user_id, product_id, plan, status, payment_provider,
                 provider_subscription_id, provider_customer_id, seat_count,
                 trial_end, current_period_start, current_period_end)
             SELECT $1, p.id, $3, 'active', $4, $5, $6, $7, $8, $9, $10
             FROM products p WHERE p.slug = $2
             RETURNING id, user_id, product_id,
                       (SELECT slug FROM products WHERE id = product_id) AS product_slug,
                       plan, status, payment_provider,
                       provider_subscription_id, provider_customer_id,
                       seat_count, trial_end, current_period_start, current_period_end,
                       created_at, updated_at",
            &[
                &user_id,
                &product_slug,
                &plan,
                &payment_provider,
                &provider_subscription_id,
                &provider_customer_id,
                &seat_count,
                &trial_end,
                &current_period_start,
                &current_period_end,
            ],
        )
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_db_error() {
                if db_err.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                    return AppError::Conflict;
                }
            }
            AppError::Database(e)
        })?;

    Ok(row_to_subscription(&row))
}

/// Cancel a subscription by setting its status to 'cancelled' (Phase 3).
#[allow(dead_code)]
pub async fn cancel_subscription(
    pool: &Pool,
    provider_subscription_id: &str,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE subscriptions
             SET status = 'cancelled', updated_at = NOW()
             WHERE provider_subscription_id = $1",
            &[&provider_subscription_id],
        )
        .await?;
    Ok(())
}

/// Ensure the user has an active Comad Individual subscription, inserting one
/// if none exists. Idempotent — safe to call on every Clann activation.
pub async fn ensure_comad_individual(pool: &Pool, user_id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO subscriptions (user_id, product_id, plan, status, seat_count)
             SELECT $1, p.id, 'individual', 'active', 1
             FROM products p
             WHERE p.slug = 'comad'
             ON CONFLICT DO NOTHING",
            &[&user_id],
        )
        .await?;
    Ok(())
}

/// Update only the status of a subscription (e.g. active → past_due).
pub async fn set_subscription_status(
    pool: &Pool,
    provider_subscription_id: &str,
    status: &str,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE subscriptions
             SET status = $2, updated_at = NOW()
             WHERE provider_subscription_id = $1",
            &[&provider_subscription_id, &status],
        )
        .await?;
    Ok(())
}

/// Sync status and billing period from a provider subscription update event.
pub async fn update_subscription_period(
    pool: &Pool,
    provider_subscription_id: &str,
    status: &str,
    trial_end: Option<DateTime<Utc>>,
    current_period_start: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE subscriptions
             SET status               = $2,
                 trial_end            = $3,
                 current_period_start = $4,
                 current_period_end   = $5,
                 updated_at           = NOW()
             WHERE provider_subscription_id = $1",
            &[
                &provider_subscription_id,
                &status,
                &trial_end,
                &current_period_start,
                &current_period_end,
            ],
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
        first_name: row.get("first_name"),
        last_name: row.get("last_name"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        confirmation_token: row.get("confirmation_token"),
        confirmation_token_expires_at: row.get("confirmation_token_expires_at"),
    }
}

fn row_to_subscription(row: &tokio_postgres::Row) -> Subscription {
    Subscription {
        id: row.get("id"),
        user_id: row.get("user_id"),
        product_id: row.get("product_id"),
        product_slug: row.get("product_slug"),
        plan: row.get("plan"),
        status: row.get("status"),
        payment_provider: row.get("payment_provider"),
        provider_subscription_id: row.get("provider_subscription_id"),
        provider_customer_id: row.get("provider_customer_id"),
        seat_count: row.get("seat_count"),
        trial_end: row.get("trial_end"),
        current_period_start: row.get("current_period_start"),
        current_period_end: row.get("current_period_end"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn row_to_user_with_roles(row: &tokio_postgres::Row) -> UserWithRoles {
    UserWithRoles {
        id: row.get("id"),
        email: row.get("email"),
        username: row.get("username"),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        roles: row.get("roles"),
    }
}

// ── Admin functions ───────────────────────────────────────────────────────────

/// List users with optional search and sort, ordered by `sort_by` column.
///
/// Returns `(users, total_count)`.
pub async fn list_users_paginated(
    pool: &Pool,
    page: i64,
    page_size: i64,
    search: &str,
    sort_by: &str,
    sort_dir: &str,
) -> Result<UsersPage, AppError> {
    let client = pool.get().await?;
    let offset = (page - 1) * page_size;

    // Whitelist sort column and direction to prevent SQL injection
    let order_col = match sort_by {
        "username" => "u.username",
        "email" => "u.email",
        _ => "u.created_at",
    };
    let order_dir = if sort_dir.eq_ignore_ascii_case("asc") { "ASC" } else { "DESC" };
    let order_clause = format!("ORDER BY {} {}", order_col, order_dir);

    let (total_row, rows) = if search.is_empty() {
        let total = client
            .query_one("SELECT COUNT(*) FROM users", &[])
            .await?;
        let rows = client
            .query(
                &format!(
                    "SELECT u.id, u.email, u.username, u.is_active, u.created_at, u.updated_at,
                            COALESCE(array_agg(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) AS roles
                     FROM users u
                     LEFT JOIN user_roles ur ON ur.user_id = u.id
                     LEFT JOIN roles r ON r.id = ur.role_id
                     GROUP BY u.id
                     {}
                     LIMIT $1 OFFSET $2",
                    order_clause
                ),
                &[&page_size, &offset],
            )
            .await?;
        (total, rows)
    } else {
        let pattern = format!("%{}%", search.to_lowercase());
        let total = client
            .query_one(
                "SELECT COUNT(*) FROM users WHERE LOWER(username) LIKE $1 OR LOWER(email) LIKE $1",
                &[&pattern],
            )
            .await?;
        let rows = client
            .query(
                &format!(
                    "SELECT u.id, u.email, u.username, u.is_active, u.created_at, u.updated_at,
                            COALESCE(array_agg(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) AS roles
                     FROM users u
                     LEFT JOIN user_roles ur ON ur.user_id = u.id
                     LEFT JOIN roles r ON r.id = ur.role_id
                     WHERE LOWER(u.username) LIKE $1 OR LOWER(u.email) LIKE $1
                     GROUP BY u.id
                     {}
                     LIMIT $2 OFFSET $3",
                    order_clause
                ),
                &[&pattern, &page_size, &offset],
            )
            .await?;
        (total, rows)
    };

    let total: i64 = total_row.get(0);
    let users = rows.iter().map(row_to_user_with_roles).collect();
    Ok(UsersPage { users, total, page, page_size })
}

/// Fetch a single user with their roles.
pub async fn get_user_with_roles(pool: &Pool, id: Uuid) -> Result<UserWithRoles, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT u.id, u.email, u.username, u.is_active, u.created_at, u.updated_at,
                    COALESCE(array_agg(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) AS roles
             FROM users u
             LEFT JOIN user_roles ur ON ur.user_id = u.id
             LEFT JOIN roles r ON r.id = ur.role_id
             WHERE u.id = $1
             GROUP BY u.id",
            &[&id],
        )
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(row_to_user_with_roles(&row))
}

/// Partially update a user's profile. NULL params leave the column unchanged.
pub async fn admin_update_user(
    pool: &Pool,
    id: Uuid,
    email: Option<&str>,
    username: Option<&str>,
    is_active: Option<bool>,
) -> Result<UserWithRoles, AppError> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE users SET
               email     = COALESCE($1, email),
               username  = COALESCE($2, username),
               is_active = COALESCE($3, is_active),
               updated_at = NOW()
             WHERE id = $4",
            &[&email, &username, &is_active, &id],
        )
        .await?;
    if updated == 0 {
        return Err(AppError::NotFound);
    }
    get_user_with_roles(pool, id).await
}

/// Delete a user by ID. Returns NotFound if the user does not exist.
pub async fn admin_delete_user(pool: &Pool, id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute("DELETE FROM users WHERE id = $1", &[&id])
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Remove a named role from a user (no-op if the role is not assigned).
pub async fn remove_role(pool: &Pool, user_id: Uuid, role_name: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "DELETE FROM user_roles
             WHERE user_id = $1
               AND role_id = (SELECT id FROM roles WHERE name = $2)",
            &[&user_id, &role_name],
        )
        .await?;
    Ok(())
}

/// List all role names defined in the system.
pub async fn list_all_roles(pool: &Pool) -> Result<Vec<String>, AppError> {
    let client = pool.get().await?;
    let rows = client.query("SELECT name FROM roles ORDER BY name", &[]).await?;
    Ok(rows.iter().map(|r| r.get("name")).collect())
}

// ── Role & permission management ──────────────────────────────────────────────

/// List all roles together with their granted permissions.
pub async fn list_roles_with_permissions(pool: &Pool) -> Result<Vec<RoleWithPermissions>, AppError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT r.name,
                    COALESCE(array_agg(p.name ORDER BY p.name) FILTER (WHERE p.name IS NOT NULL), ARRAY[]::text[]) AS permissions
             FROM roles r
             LEFT JOIN role_permissions rp ON rp.role_id = r.id
             LEFT JOIN permissions p ON p.id = rp.permission_id
             GROUP BY r.name
             ORDER BY r.name",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| RoleWithPermissions {
            name: row.get("name"),
            permissions: row.get("permissions"),
        })
        .collect())
}

/// List all permission names defined in the system.
pub async fn list_all_permissions(pool: &Pool) -> Result<Vec<String>, AppError> {
    let client = pool.get().await?;
    let rows = client.query("SELECT name FROM permissions ORDER BY name", &[]).await?;
    Ok(rows.iter().map(|r| r.get("name")).collect())
}

/// Create a new role. Returns Conflict if the name already exists.
pub async fn create_role(pool: &Pool, name: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute("INSERT INTO roles (name) VALUES ($1)", &[&name])
        .await
        .map_err(|e| {
            if let Some(db) = e.as_db_error() {
                if db.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                    return AppError::Conflict;
                }
            }
            AppError::Database(e)
        })?;
    Ok(())
}

/// Delete a role by name.
pub async fn delete_role(pool: &Pool, name: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute("DELETE FROM roles WHERE name = $1", &[&name])
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Create a new permission. No-op if already exists.
pub async fn create_permission(pool: &Pool, name: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO permissions (name) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&name],
        )
        .await?;
    Ok(())
}

/// Grant a permission to a role (no-op if already granted).
pub async fn add_permission_to_role(pool: &Pool, role: &str, permission: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    let affected = client
        .execute(
            "INSERT INTO role_permissions (role_id, permission_id)
             SELECT r.id, p.id FROM roles r, permissions p
             WHERE r.name = $1 AND p.name = $2
             ON CONFLICT DO NOTHING",
            &[&role, &permission],
        )
        .await?;
    if affected == 0 {
        // Role or permission not found
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Revoke a permission from a role.
pub async fn remove_permission_from_role(pool: &Pool, role: &str, permission: &str) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "DELETE FROM role_permissions
             WHERE role_id       = (SELECT id FROM roles       WHERE name = $1)
               AND permission_id = (SELECT id FROM permissions WHERE name = $2)",
            &[&role, &permission],
        )
        .await?;
    Ok(())
}

// ── Subscription management ───────────────────────────────────────────────────

/// List all subscriptions across all users with optional search and product filter.
pub async fn list_subscriptions_paginated(
    pool: &Pool,
    page: i64,
    page_size: i64,
    search: &str,
    product: &str,
) -> Result<SubscriptionsPage, AppError> {
    let client = pool.get().await?;
    let offset = (page - 1) * page_size;

    // Build WHERE clauses dynamically based on filters.
    // We use a single-branch approach: always include both filters, treating
    // empty strings as "match all".
    let search_pattern = if search.is_empty() {
        "%".to_string()
    } else {
        format!("%{}%", search.to_lowercase())
    };
    let product_pattern = if product.is_empty() {
        "%".to_string()
    } else {
        product.to_string()
    };

    let total_row = client
        .query_one(
            "SELECT COUNT(*) FROM subscriptions s
             JOIN users    u ON u.id = s.user_id
             JOIN products p ON p.id = s.product_id
             WHERE (LOWER(u.username) LIKE $1 OR LOWER(u.email) LIKE $1)
               AND ($2 = '%' OR p.slug = $2)",
            &[&search_pattern, &product_pattern],
        )
        .await?;
    let total: i64 = total_row.get(0);

    let rows = client
        .query(
            "SELECT s.id, s.user_id, u.username, u.email,
                    p.slug AS product, p.name AS product_name,
                    s.plan, s.status, s.seat_count,
                    s.trial_end, s.current_period_start, s.current_period_end,
                    s.created_at, s.updated_at
             FROM subscriptions s
             JOIN users    u ON u.id = s.user_id
             JOIN products p ON p.id = s.product_id
             WHERE (LOWER(u.username) LIKE $1 OR LOWER(u.email) LIKE $1)
               AND ($2 = '%' OR p.slug = $2)
             ORDER BY s.created_at DESC
             LIMIT $3 OFFSET $4",
            &[&search_pattern, &product_pattern, &page_size, &offset],
        )
        .await?;

    let subscriptions = rows.iter().map(row_to_admin_subscription).collect();
    Ok(SubscriptionsPage { subscriptions, total, page, page_size })
}

/// Fetch a single subscription by ID.
pub async fn admin_get_subscription(pool: &Pool, id: Uuid) -> Result<AdminSubscription, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT s.id, s.user_id, u.username, u.email,
                    p.slug AS product, p.name AS product_name,
                    s.plan, s.status, s.seat_count,
                    s.trial_end, s.current_period_start, s.current_period_end,
                    s.created_at, s.updated_at
             FROM subscriptions s
             JOIN users    u ON u.id = s.user_id
             JOIN products p ON p.id = s.product_id
             WHERE s.id = $1",
            &[&id],
        )
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(row_to_admin_subscription(&row))
}

/// Partially update a subscription's plan, status, or seat count.
pub async fn admin_update_subscription(
    pool: &Pool,
    id: Uuid,
    plan: Option<&str>,
    status: Option<&str>,
    seat_count: Option<i16>,
) -> Result<AdminSubscription, AppError> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE subscriptions SET
               plan       = COALESCE($1, plan),
               status     = COALESCE($2, status),
               seat_count = COALESCE($3, seat_count),
               updated_at = NOW()
             WHERE id = $4",
            &[&plan, &status, &seat_count, &id],
        )
        .await?;
    if updated == 0 {
        return Err(AppError::NotFound);
    }
    admin_get_subscription(pool, id).await
}

/// Create a new subscription for a user.
pub async fn admin_create_subscription(
    pool: &Pool,
    user_id: Uuid,
    product_slug: &str,
    plan: &str,
    status: &str,
    seat_count: i16,
) -> Result<AdminSubscription, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "INSERT INTO subscriptions (user_id, product_id, plan, status, seat_count)
             SELECT $1, p.id, $3, $4, $5 FROM products p WHERE p.slug = $2
             RETURNING id",
            &[&user_id, &product_slug, &plan, &status, &seat_count],
        )
        .await
        .map_err(|e| {
            if let Some(db) = e.as_db_error() {
                if db.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                    return AppError::Conflict;
                }
            }
            AppError::Database(e)
        })?;
    let new_id: Uuid = row.get("id");
    admin_get_subscription(pool, new_id).await
}

/// Delete a subscription by ID.
pub async fn admin_delete_subscription(pool: &Pool, id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute("DELETE FROM subscriptions WHERE id = $1", &[&id])
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// List all products.
pub async fn list_products(pool: &Pool) -> Result<Vec<ProductResponse>, AppError> {
    let client = pool.get().await?;
    let rows = client
        .query("SELECT slug, name FROM products ORDER BY name", &[])
        .await?;
    Ok(rows
        .iter()
        .map(|r| ProductResponse { slug: r.get("slug"), name: r.get("name") })
        .collect())
}

// ── Plan management ───────────────────────────────────────────────────────────

/// List plans, optionally filtered to a single product by slug.
pub async fn list_plans(pool: &Pool, product_slug: &str) -> Result<Vec<PlanResponse>, AppError> {
    let client = pool.get().await?;
    let rows = if product_slug.is_empty() {
        client
            .query(
                "SELECT pl.id, pr.slug AS product_slug, pl.slug, pl.name
                 FROM plans pl
                 JOIN products pr ON pr.id = pl.product_id
                 ORDER BY pr.name, pl.name",
                &[],
            )
            .await?
    } else {
        client
            .query(
                "SELECT pl.id, pr.slug AS product_slug, pl.slug, pl.name
                 FROM plans pl
                 JOIN products pr ON pr.id = pl.product_id
                 WHERE pr.slug = $1
                 ORDER BY pl.name",
                &[&product_slug],
            )
            .await?
    };
    Ok(rows
        .iter()
        .map(|r| PlanResponse {
            id: r.get("id"),
            product_slug: r.get("product_slug"),
            slug: r.get("slug"),
            name: r.get("name"),
        })
        .collect())
}

/// Create a new plan for a product (identified by slug).
pub async fn create_plan(pool: &Pool, product_slug: &str, slug: &str, name: &str) -> Result<PlanResponse, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "INSERT INTO plans (product_id, slug, name)
             SELECT p.id, $2, $3 FROM products p WHERE p.slug = $1
             RETURNING id",
            &[&product_slug, &slug, &name],
        )
        .await
        .map_err(|e| {
            if let Some(db) = e.as_db_error() {
                if db.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                    return AppError::Conflict;
                }
            }
            AppError::Database(e)
        })?;
    let id: Uuid = row.get("id");
    let fetched = client
        .query_one(
            "SELECT pl.id, pr.slug AS product_slug, pl.slug, pl.name
             FROM plans pl JOIN products pr ON pr.id = pl.product_id
             WHERE pl.id = $1",
            &[&id],
        )
        .await?;
    Ok(PlanResponse {
        id: fetched.get("id"),
        product_slug: fetched.get("product_slug"),
        slug: fetched.get("slug"),
        name: fetched.get("name"),
    })
}

/// Delete a plan by ID.
pub async fn delete_plan(pool: &Pool, id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute("DELETE FROM plans WHERE id = $1", &[&id])
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

fn row_to_admin_subscription(row: &tokio_postgres::Row) -> AdminSubscription {
    AdminSubscription {
        id: row.get("id"),
        user_id: row.get("user_id"),
        username: row.get("username"),
        email: row.get("email"),
        product: row.get("product"),
        product_name: row.get("product_name"),
        plan: row.get("plan"),
        status: row.get("status"),
        seat_count: row.get("seat_count"),
        trial_end: row.get("trial_end"),
        current_period_start: row.get("current_period_start"),
        current_period_end: row.get("current_period_end"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}
