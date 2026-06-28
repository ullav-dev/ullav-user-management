pub mod oauth2;

use crate::errors::AppError;
use crate::models::{
    AdminSubscription, PasswordResetToken, PlanResponse, ProductResponse, RoleWithPermissions,
    Subscription, SubscriptionsPage, TeamMemberResponse, TeamMemberRow, TeamProductAccessResponse,
    TeamProductRef, TeamResponse, TeamRoleResponse, TeamSummary, TeamUserRef, TeamsPage, User,
    UserTeamAccess, UserWithRoles, UsersPage,
};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use std::collections::HashMap;
use uuid::Uuid;

/// Active team membership data used when building the JWT teams claim.
pub struct ActiveTeamInfo {
    pub team_id: String,
    pub name: String,
    pub role: String,
    /// Names of custom team roles assigned to this member.
    pub team_roles: Vec<String>,
    /// Product-specific access roles: product_slug → role (e.g. "obair" → "admin").
    pub product_roles: HashMap<String, String>,
    /// Product slugs enabled for the team at the team level (from `team_product_access`).
    pub products: Vec<String>,
}

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
                       avatar_url, created_at, updated_at, confirmation_token, confirmation_token_expires_at",
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

/// Create a new user as immediately active (admin provisioning, no email confirmation).
pub async fn admin_create_user(
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
             VALUES ($1, $2, $3, TRUE, $4, $5)
             RETURNING id, email, username, password_hash, is_active, first_name, last_name,
                       avatar_url, created_at, updated_at, confirmation_token, confirmation_token_expires_at",
            &[&email, &username, &password_hash, &first_name, &last_name],
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

    Ok(row_to_user(&row))
}

/// Fetch a user by their UUID.
pub async fn get_user_by_id(pool: &Pool, id: Uuid) -> Result<User, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, email, username, password_hash, is_active, first_name, last_name,
                    avatar_url, created_at, updated_at, confirmation_token, confirmation_token_expires_at
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
                    avatar_url, created_at, updated_at, confirmation_token, confirmation_token_expires_at
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
                    avatar_url, created_at, updated_at, confirmation_token, confirmation_token_expires_at
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
        avatar_url: row.get("avatar_url"),
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
        first_name: row.get("first_name"),
        last_name: row.get("last_name"),
        avatar_url: row.get("avatar_url"),
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
                    "SELECT u.id, u.email, u.username, u.is_active, u.first_name, u.last_name, u.avatar_url, u.created_at, u.updated_at,
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
                    "SELECT u.id, u.email, u.username, u.is_active, u.first_name, u.last_name, u.avatar_url, u.created_at, u.updated_at,
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
            "SELECT u.id, u.email, u.username, u.is_active, u.first_name, u.last_name, u.avatar_url, u.created_at, u.updated_at,
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

/// Update a user's own profile fields. `avatar_url` uses two params to support
/// clear (Some(None)) vs no-change (None) vs set (Some(Some(v))).
pub async fn update_user_profile(
    pool: &Pool,
    user_id: Uuid,
    first_name: Option<&str>,
    last_name: Option<&str>,
    avatar_url: Option<Option<&str>>,
) -> Result<User, AppError> {
    let clear_avatar = matches!(avatar_url, Some(None));
    let new_avatar = avatar_url.flatten();
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "UPDATE users SET
               first_name = COALESCE($2::text, first_name),
               last_name  = COALESCE($3::text, last_name),
               avatar_url = CASE
                   WHEN $4::bool        THEN NULL
                   WHEN $5::text IS NOT NULL THEN $5::text
                   ELSE avatar_url
               END,
               updated_at = NOW()
             WHERE id = $1
             RETURNING id, email, username, password_hash, is_active, first_name, last_name,
                       avatar_url, created_at, updated_at, confirmation_token,
                       confirmation_token_expires_at",
            &[&user_id, &first_name, &last_name, &clear_avatar, &new_avatar],
        )
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(row_to_user(&row))
}

/// Partially update a user's profile (admin). NULL params leave the column unchanged.
/// For nullable text fields, pass Some(None) to clear and None to leave unchanged.
pub async fn admin_update_user(
    pool: &Pool,
    id: Uuid,
    email: Option<&str>,
    username: Option<&str>,
    is_active: Option<bool>,
    first_name: Option<Option<&str>>,
    last_name: Option<Option<&str>>,
    avatar_url: Option<Option<&str>>,
) -> Result<UserWithRoles, AppError> {
    let clear_first_name = matches!(first_name, Some(None));
    let new_first_name = first_name.flatten();
    let clear_last_name = matches!(last_name, Some(None));
    let new_last_name = last_name.flatten();
    let clear_avatar = matches!(avatar_url, Some(None));
    let new_avatar = avatar_url.flatten();
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE users SET
               email      = COALESCE($1, email),
               username   = COALESCE($2, username),
               is_active  = COALESCE($3, is_active),
               first_name = CASE WHEN $4 THEN NULL WHEN $5::text IS NOT NULL THEN $5 ELSE first_name END,
               last_name  = CASE WHEN $6 THEN NULL WHEN $7::text IS NOT NULL THEN $7 ELSE last_name  END,
               avatar_url = CASE WHEN $8 THEN NULL WHEN $9::text IS NOT NULL THEN $9 ELSE avatar_url  END,
               updated_at = NOW()
             WHERE id = $10",
            &[
                &email, &username, &is_active,
                &clear_first_name, &new_first_name,
                &clear_last_name, &new_last_name,
                &clear_avatar, &new_avatar,
                &id,
            ],
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

// ── Teams ─────────────────────────────────────────────────────────────────────

/// Create a team and atomically add the owner as the first active member.
/// Returns the new team's UUID.
pub async fn create_team(
    pool: &Pool,
    name: &str,
    description: Option<&str>,
    purpose: Option<&str>,
    avatar_url: Option<&str>,
    owner_id: Uuid,
) -> Result<Uuid, AppError> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;

    let row = tx
        .query_one(
            "INSERT INTO teams (name, description, purpose, avatar_url, owner_id, leader_id)
             VALUES ($1, $2, $3, $4, $5, $5)
             RETURNING id",
            &[&name, &description, &purpose, &avatar_url, &owner_id],
        )
        .await?;

    let team_id: Uuid = row.get("id");

    tx.execute(
        "INSERT INTO team_members (team_id, user_id, status, joined_at)
         VALUES ($1, $2, 'active', NOW())",
        &[&team_id, &owner_id],
    )
    .await?;

    tx.commit().await?;
    Ok(team_id)
}

/// Fetch the owner_id and leader_id for a team. Returns NotFound if the team does not exist.
pub async fn get_team_ownership(pool: &Pool, team_id: Uuid) -> Result<(Uuid, Uuid), AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT owner_id, leader_id FROM teams WHERE id = $1",
            &[&team_id],
        )
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((row.get("owner_id"), row.get("leader_id")))
}

/// Fetch a full team response including all non-inactive members and their team roles.
pub async fn get_team_response(pool: &Pool, team_id: Uuid) -> Result<TeamResponse, AppError> {
    let client = pool.get().await?;

    let team_row = client
        .query_opt(
            "SELECT t.id, t.name, t.description, t.purpose, t.avatar_url,
                    t.owner_id,
                    o.username AS owner_username, o.email AS owner_email,
                    o.first_name AS owner_first_name, o.last_name AS owner_last_name,
                    o.avatar_url AS owner_avatar_url,
                    t.leader_id,
                    l.username AS leader_username, l.email AS leader_email,
                    l.first_name AS leader_first_name, l.last_name AS leader_last_name,
                    l.avatar_url AS leader_avatar_url,
                    t.created_at, t.updated_at
             FROM teams t
             JOIN users o ON o.id = t.owner_id
             JOIN users l ON l.id = t.leader_id
             WHERE t.id = $1",
            &[&team_id],
        )
        .await?
        .ok_or(AppError::NotFound)?;

    let member_rows = client
        .query(
            "SELECT tm.id, tm.user_id,
                    u.username, u.email, u.first_name, u.last_name, u.avatar_url,
                    tm.status::text,
                    CASE
                        WHEN tm.user_id = t.owner_id  THEN 'owner'
                        WHEN tm.user_id = t.leader_id THEN 'leader'
                        ELSE 'member'
                    END AS role,
                    tm.invited_at, tm.joined_at
             FROM team_members tm
             JOIN users u ON u.id = tm.user_id
             JOIN teams t ON t.id = tm.team_id
             WHERE tm.team_id = $1 AND tm.status != 'inactive'
             ORDER BY tm.joined_at NULLS LAST, tm.invited_at",
            &[&team_id],
        )
        .await?;

    // Fetch all role assignments for this team in one query, keyed by team_members.id.
    let role_rows = client
        .query(
            "SELECT tmr.member_id, tr.id AS role_id, tr.name, tr.description,
                    tr.created_at, tr.updated_at
             FROM team_member_roles tmr
             JOIN team_roles tr ON tr.id = tmr.role_id
             WHERE tmr.team_id = $1",
            &[&team_id],
        )
        .await?;

    let mut roles_by_member: HashMap<Uuid, Vec<TeamRoleResponse>> = HashMap::new();
    for row in &role_rows {
        let member_id: Uuid = row.get("member_id");
        roles_by_member.entry(member_id).or_default().push(TeamRoleResponse {
            id: row.get("role_id"),
            name: row.get("name"),
            description: row.get("description"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        });
    }

    // Fetch per-member product roles for this team.
    let product_role_rows = client
        .query(
            "SELECT user_id, product_slug, role FROM team_member_product_roles WHERE team_id = $1",
            &[&team_id],
        )
        .await?;
    let mut product_roles_by_user: HashMap<Uuid, HashMap<String, String>> = HashMap::new();
    for row in &product_role_rows {
        let user_id: Uuid = row.get("user_id");
        let slug: String = row.get("product_slug");
        let role: String = row.get("role");
        product_roles_by_user.entry(user_id).or_default().insert(slug, role);
    }

    Ok(row_to_team_response(&team_row, &member_rows, &roles_by_member, &product_roles_by_user))
}

/// List teams where the user is an active member, returning lightweight summaries.
pub async fn list_user_teams(pool: &Pool, user_id: Uuid) -> Result<Vec<TeamSummary>, AppError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT t.id, t.name, t.description, t.avatar_url,
                    t.owner_id,
                    o.username AS owner_username, o.email AS owner_email,
                    o.first_name AS owner_first_name, o.last_name AS owner_last_name,
                    o.avatar_url AS owner_avatar_url,
                    t.leader_id,
                    l.username AS leader_username, l.email AS leader_email,
                    l.first_name AS leader_first_name, l.last_name AS leader_last_name,
                    l.avatar_url AS leader_avatar_url,
                    COUNT(m.id) FILTER (WHERE m.status = 'active') AS member_count,
                    t.created_at, t.updated_at
             FROM teams t
             JOIN users o ON o.id = t.owner_id
             JOIN users l ON l.id = t.leader_id
             JOIN team_members me ON me.team_id = t.id AND me.user_id = $1 AND me.status = 'active'
             LEFT JOIN team_members m ON m.team_id = t.id
             GROUP BY t.id, o.id, l.id
             ORDER BY t.name",
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_team_summary).collect())
}

/// Update a team's editable fields. Null parameters leave columns unchanged.
pub async fn update_team(
    pool: &Pool,
    team_id: Uuid,
    name: Option<&str>,
    description: Option<&str>,
    purpose: Option<&str>,
    avatar_url: Option<&str>,
    leader_id: Option<Uuid>,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE teams SET
               name        = COALESCE($1, name),
               description = COALESCE($2, description),
               purpose     = COALESCE($3, purpose),
               avatar_url  = COALESCE($4, avatar_url),
               leader_id   = COALESCE($5, leader_id),
               updated_at  = NOW()
             WHERE id = $6",
            &[&name, &description, &purpose, &avatar_url, &leader_id, &team_id],
        )
        .await?;
    if updated == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Admin variant: can also change owner_id.
pub async fn admin_update_team(
    pool: &Pool,
    team_id: Uuid,
    name: Option<&str>,
    description: Option<&str>,
    purpose: Option<&str>,
    avatar_url: Option<&str>,
    owner_id: Option<Uuid>,
    leader_id: Option<Uuid>,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE teams SET
               name        = COALESCE($1, name),
               description = COALESCE($2, description),
               purpose     = COALESCE($3, purpose),
               avatar_url  = COALESCE($4, avatar_url),
               owner_id    = COALESCE($5, owner_id),
               leader_id   = COALESCE($6, leader_id),
               updated_at  = NOW()
             WHERE id = $7",
            &[&name, &description, &purpose, &avatar_url, &owner_id, &leader_id, &team_id],
        )
        .await?;
    if updated == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Delete a team by ID. Cascades to team_members.
pub async fn delete_team(pool: &Pool, team_id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute("DELETE FROM teams WHERE id = $1", &[&team_id])
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Check whether a user is already a member (any status) of a team.
pub async fn get_team_membership(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<Option<TeamMemberRow>, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, team_id, user_id, status::text,
                    invite_token_expires_at, invited_at, joined_at
             FROM team_members WHERE team_id = $1 AND user_id = $2",
            &[&team_id, &user_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_team_member_row))
}

/// Create a pending invitation row. Returns Conflict if the user is already a member.
pub async fn invite_team_member(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
    invited_by: Uuid,
    token: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO team_members
                (team_id, user_id, status, invited_by, invite_token, invite_token_expires_at, invited_at)
             VALUES ($1, $2, 'invited', $3, $4, $5, NOW())",
            &[&team_id, &user_id, &invited_by, &token, &expires_at],
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
    Ok(())
}

/// Directly add a user as an active member (admin bypass — skips invite flow).
pub async fn add_team_member_active(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
    added_by: Uuid,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO team_members
                (team_id, user_id, status, invited_by, joined_at)
             VALUES ($1, $2, 'active', $3, NOW())
             ON CONFLICT (team_id, user_id) DO UPDATE
             SET status = 'active', joined_at = COALESCE(team_members.joined_at, NOW())",
            &[&team_id, &user_id, &added_by],
        )
        .await?;
    Ok(())
}

/// Retrieve a team_members row by invitation token.
pub async fn get_team_member_by_token(
    pool: &Pool,
    token: &str,
) -> Result<TeamMemberRow, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, team_id, user_id, status::text,
                    invite_token_expires_at, invited_at, joined_at
             FROM team_members WHERE invite_token = $1",
            &[&token],
        )
        .await?
        .ok_or(AppError::InvalidToken)?;
    Ok(row_to_team_member_row(&row))
}

/// Accept an invitation: set status to active, record joined_at, clear the token.
pub async fn accept_team_invitation(pool: &Pool, member_id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE team_members
             SET status = 'active', joined_at = NOW(),
                 invite_token = NULL, invite_token_expires_at = NULL
             WHERE id = $1",
            &[&member_id],
        )
        .await?;
    Ok(())
}

/// Decline an invitation: delete the membership row entirely.
pub async fn decline_team_invitation(pool: &Pool, member_id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute("DELETE FROM team_members WHERE id = $1", &[&member_id])
        .await?;
    Ok(())
}

/// Remove an active/invited member from a team.
pub async fn remove_team_member(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute(
            "DELETE FROM team_members WHERE team_id = $1 AND user_id = $2",
            &[&team_id, &user_id],
        )
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Replace an invited member's token + expiry so a fresh invite email can be sent.
/// Returns NotFound if the member is not in "invited" status.
pub async fn refresh_invite_token(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
    new_token: &str,
    new_expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE team_members
             SET invite_token = $3, invite_token_expires_at = $4, invited_at = NOW()
             WHERE team_id = $1 AND user_id = $2 AND status = 'invited'",
            &[&team_id, &user_id, &new_token, &new_expires_at],
        )
        .await?;
    if updated == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Fetch all active team memberships for a user to embed in the JWT.
///
/// Uses correlated subqueries for team_roles and product_roles to avoid
/// a cartesian product when a member has both custom roles and product roles.
pub async fn get_user_active_teams(
    pool: &Pool,
    user_id: Uuid,
) -> Result<Vec<ActiveTeamInfo>, AppError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT t.id::text AS team_id, t.name,
                    CASE
                        WHEN tm.user_id = t.owner_id  THEN 'owner'
                        WHEN tm.user_id = t.leader_id THEN 'leader'
                        ELSE 'member'
                    END AS role,
                    (
                        SELECT COALESCE(ARRAY_AGG(tr2.name ORDER BY tr2.name), '{}'::text[])
                        FROM team_member_roles tmr2
                        JOIN team_roles tr2 ON tr2.id = tmr2.role_id
                        WHERE tmr2.member_id = tm.id
                    ) AS team_role_names,
                    (
                        SELECT COALESCE(ARRAY_AGG(tpa.product_slug ORDER BY tpa.product_slug), '{}'::text[])
                        FROM team_product_access tpa
                        WHERE tpa.team_id = t.id
                    ) AS product_slugs
             FROM team_members tm
             JOIN teams t ON t.id = tm.team_id
             WHERE tm.user_id = $1 AND tm.status = 'active'
             ORDER BY t.name",
            &[&user_id],
        )
        .await?;

    // Fetch product roles in a single query and group by team in application code.
    // Kept separate from the teams query to avoid a cartesian product with team_roles.
    let pr_rows = client
        .query(
            "SELECT team_id::text, product_slug, role
             FROM team_member_product_roles
             WHERE user_id = $1",
            &[&user_id],
        )
        .await?;

    let mut product_roles_by_team: HashMap<String, HashMap<String, String>> = HashMap::new();
    for row in &pr_rows {
        let tid: String = row.get("team_id");
        let slug: String = row.get("product_slug");
        let role: String = row.get("role");
        product_roles_by_team.entry(tid).or_default().insert(slug, role);
    }

    Ok(rows
        .iter()
        .map(|r| {
            let team_id: String = r.get("team_id");
            let product_roles = product_roles_by_team.remove(&team_id).unwrap_or_default();
            ActiveTeamInfo {
                team_id,
                name: r.get("name"),
                role: r.get("role"),
                team_roles: r.get("team_role_names"),
                product_roles,
                products: r.get("product_slugs"),
            }
        })
        .collect())
}

/// List teams with optional search, paginated — for the admin panel.
pub async fn list_teams_paginated(
    pool: &Pool,
    page: i64,
    page_size: i64,
    search: &str,
    product_slug: &str,
) -> Result<TeamsPage, AppError> {
    let client = pool.get().await?;
    let offset = (page - 1) * page_size;
    let pattern = if search.is_empty() {
        "%".to_string()
    } else {
        format!("%{}%", search.to_lowercase())
    };

    // Empty product_slug means "all teams"; non-empty restricts to teams
    // that have the given product enabled in team_product_access.
    let total_row = client
        .query_one(
            "SELECT COUNT(*) FROM teams t
             JOIN users o ON o.id = t.owner_id
             WHERE (LOWER(t.name) LIKE $1 OR LOWER(o.username) LIKE $1)
               AND ($2 = '' OR EXISTS (
                   SELECT 1 FROM team_product_access tpa
                   WHERE tpa.team_id = t.id AND tpa.product_slug = $2
               ))",
            &[&pattern, &product_slug],
        )
        .await?;
    let total: i64 = total_row.get(0);

    let rows = client
        .query(
            "SELECT t.id, t.name, t.description, t.avatar_url,
                    t.owner_id,
                    o.username AS owner_username, o.email AS owner_email,
                    o.first_name AS owner_first_name, o.last_name AS owner_last_name,
                    o.avatar_url AS owner_avatar_url,
                    t.leader_id,
                    l.username AS leader_username, l.email AS leader_email,
                    l.first_name AS leader_first_name, l.last_name AS leader_last_name,
                    l.avatar_url AS leader_avatar_url,
                    COUNT(m.id) FILTER (WHERE m.status = 'active') AS member_count,
                    t.created_at, t.updated_at
             FROM teams t
             JOIN users o ON o.id = t.owner_id
             JOIN users l ON l.id = t.leader_id
             LEFT JOIN team_members m ON m.team_id = t.id
             WHERE (LOWER(t.name) LIKE $1 OR LOWER(o.username) LIKE $1)
               AND ($2 = '' OR EXISTS (
                   SELECT 1 FROM team_product_access tpa
                   WHERE tpa.team_id = t.id AND tpa.product_slug = $2
               ))
             GROUP BY t.id, o.id, l.id
             ORDER BY t.name
             LIMIT $3 OFFSET $4",
            &[&pattern, &product_slug, &page_size, &offset],
        )
        .await?;

    let teams = rows.iter().map(row_to_team_summary).collect();
    Ok(TeamsPage { teams, total, page, page_size })
}

// ── Team roles ────────────────────────────────────────────────────────────────

/// List all roles defined for a team, ordered by name.
pub async fn list_team_roles(pool: &Pool, team_id: Uuid) -> Result<Vec<TeamRoleResponse>, AppError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, name, description, created_at, updated_at
             FROM team_roles WHERE team_id = $1 ORDER BY name",
            &[&team_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_team_role).collect())
}

/// Create a new role for a team. Returns Conflict if the name already exists in that team.
pub async fn create_team_role(
    pool: &Pool,
    team_id: Uuid,
    name: &str,
    description: Option<&str>,
) -> Result<TeamRoleResponse, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "INSERT INTO team_roles (team_id, name, description)
             VALUES ($1, $2, $3)
             RETURNING id, name, description, created_at, updated_at",
            &[&team_id, &name, &description],
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
    Ok(row_to_team_role(&row))
}

/// Update a team role's name and/or description. Returns NotFound if the role does not belong
/// to the given team. Returns Conflict on duplicate name.
pub async fn update_team_role(
    pool: &Pool,
    team_id: Uuid,
    role_id: Uuid,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<TeamRoleResponse, AppError> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "UPDATE team_roles SET
               name        = COALESCE($3, name),
               description = COALESCE($4, description),
               updated_at  = NOW()
             WHERE id = $1 AND team_id = $2
             RETURNING id, name, description, created_at, updated_at",
            &[&role_id, &team_id, &name, &description],
        )
        .await
        .map_err(|e| {
            if let Some(db) = e.as_db_error() {
                if db.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
                    return AppError::Conflict;
                }
            }
            AppError::Database(e)
        })?
        .ok_or(AppError::NotFound)?;
    Ok(row_to_team_role(&row))
}

/// Delete a team role. Cascades to remove all member assignments for that role.
pub async fn delete_team_role(pool: &Pool, team_id: Uuid, role_id: Uuid) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute(
            "DELETE FROM team_roles WHERE id = $1 AND team_id = $2",
            &[&role_id, &team_id],
        )
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Assign a team role to an active team member.
/// Returns Validation if the user is not an active member, Conflict if already assigned,
/// or NotFound if the role does not belong to the given team.
pub async fn assign_member_role(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let affected = client
        .execute(
            "INSERT INTO team_member_roles (team_id, role_id, member_id)
             SELECT $1, $2, tm.id
             FROM team_members tm
             WHERE tm.team_id = $1 AND tm.user_id = $3 AND tm.status = 'active'",
            &[&team_id, &role_id, &user_id],
        )
        .await
        .map_err(|e| {
            if let Some(db) = e.as_db_error() {
                return match db.code() {
                    &tokio_postgres::error::SqlState::UNIQUE_VIOLATION => AppError::Conflict,
                    &tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION => AppError::NotFound,
                    _ => AppError::Database(e),
                };
            }
            AppError::Database(e)
        })?;
    if affected == 0 {
        return Err(AppError::Validation(
            "user is not an active member of this team".into(),
        ));
    }
    Ok(())
}

/// Remove a team role assignment from a member.
pub async fn unassign_member_role(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute(
            "DELETE FROM team_member_roles tmr
             USING team_members tm
             WHERE tmr.role_id = $1
               AND tmr.member_id = tm.id
               AND tm.team_id = $2
               AND tm.user_id = $3",
            &[&role_id, &team_id, &user_id],
        )
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

// ── Team product access ───────────────────────────────────────────────────────

/// Enable a product for a team. Idempotent — does nothing if already enabled.
pub async fn enable_team_product(
    pool: &Pool,
    team_id: Uuid,
    product_slug: &str,
    granted_by: Uuid,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO team_product_access (team_id, product_slug, granted_by)
             VALUES ($1, $2, $3)
             ON CONFLICT (team_id, product_slug) DO NOTHING",
            &[&team_id, &product_slug, &granted_by],
        )
        .await?;
    Ok(())
}

/// Disable a product for a team.
/// Returns NotFound if the team did not have the product enabled.
/// Cascades: all team_member_product_roles for this (team, product) are deleted automatically.
pub async fn disable_team_product(
    pool: &Pool,
    team_id: Uuid,
    product_slug: &str,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute(
            "DELETE FROM team_product_access WHERE team_id = $1 AND product_slug = $2",
            &[&team_id, &product_slug],
        )
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// List all products enabled for a team.
pub async fn list_team_products(
    pool: &Pool,
    team_id: Uuid,
) -> Result<Vec<TeamProductAccessResponse>, AppError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT p.slug AS product_slug, p.name AS product_name,
                    tpa.granted_at, u.username AS granted_by_username
             FROM team_product_access tpa
             JOIN products p ON p.slug = tpa.product_slug
             LEFT JOIN users u ON u.id = tpa.granted_by
             WHERE tpa.team_id = $1
             ORDER BY p.name",
            &[&team_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| TeamProductAccessResponse {
            product_slug: r.get("product_slug"),
            product_name: r.get("product_name"),
            granted_at: r.get("granted_at"),
            granted_by_username: r.get("granted_by_username"),
        })
        .collect())
}

/// Assign (or update) a product role for a team member.
///
/// Upserts so calling again with a different role updates the existing assignment.
/// Converts FK violations into descriptive Validation errors rather than 500s.
pub async fn assign_member_product_role(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
    product_slug: &str,
    role: &str,
    assigned_by: Uuid,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO team_member_product_roles
                 (team_id, user_id, product_slug, role, assigned_by)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (team_id, user_id, product_slug)
             DO UPDATE SET role = EXCLUDED.role, assigned_by = EXCLUDED.assigned_by,
                           assigned_at = NOW()",
            &[&team_id, &user_id, &product_slug, &role, &assigned_by],
        )
        .await
        .map_err(|e| {
            if let Some(db_err) = e.as_db_error() {
                if db_err.code() == &tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION {
                    let msg = db_err.message();
                    if msg.contains("team_product_access") {
                        return AppError::Validation(
                            "team does not have this product enabled".into(),
                        );
                    }
                    if msg.contains("team_members") {
                        return AppError::Validation(
                            "user is not an active member of this team".into(),
                        );
                    }
                }
            }
            AppError::Database(e)
        })?;
    Ok(())
}

/// Revoke a product role from a team member.
/// Returns NotFound if no assignment exists.
pub async fn revoke_member_product_role(
    pool: &Pool,
    team_id: Uuid,
    user_id: Uuid,
    product_slug: &str,
) -> Result<(), AppError> {
    let client = pool.get().await?;
    let deleted = client
        .execute(
            "DELETE FROM team_member_product_roles
             WHERE team_id = $1 AND user_id = $2 AND product_slug = $3",
            &[&team_id, &user_id, &product_slug],
        )
        .await?;
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

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

fn row_to_team_user_ref(
    row: &tokio_postgres::Row,
    id_col: &str,
    username_col: &str,
    email_col: &str,
    first_name_col: &str,
    last_name_col: &str,
    avatar_url_col: &str,
) -> TeamUserRef {
    TeamUserRef {
        id: row.get(id_col),
        username: row.get(username_col),
        email: row.get(email_col),
        first_name: row.get(first_name_col),
        last_name: row.get(last_name_col),
        avatar_url: row.get(avatar_url_col),
    }
}

fn row_to_team_summary(row: &tokio_postgres::Row) -> TeamSummary {
    TeamSummary {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        avatar_url: row.get("avatar_url"),
        owner: row_to_team_user_ref(
            row, "owner_id", "owner_username", "owner_email",
            "owner_first_name", "owner_last_name", "owner_avatar_url",
        ),
        leader: row_to_team_user_ref(
            row, "leader_id", "leader_username", "leader_email",
            "leader_first_name", "leader_last_name", "leader_avatar_url",
        ),
        member_count: row.get("member_count"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn row_to_team_response(
    team_row: &tokio_postgres::Row,
    member_rows: &[tokio_postgres::Row],
    roles_by_member: &HashMap<Uuid, Vec<TeamRoleResponse>>,
    product_roles_by_user: &HashMap<Uuid, HashMap<String, String>>,
) -> TeamResponse {
    let members = member_rows
        .iter()
        .map(|r| {
            let member_id: Uuid = r.get("id");
            let user_id: Uuid = r.get("user_id");
            TeamMemberResponse {
                id: member_id,
                user: TeamUserRef {
                    id: user_id,
                    username: r.get("username"),
                    email: r.get("email"),
                    first_name: r.get("first_name"),
                    last_name: r.get("last_name"),
                    avatar_url: r.get("avatar_url"),
                },
                status: r.get("status"),
                role: r.get("role"),
                team_roles: roles_by_member.get(&member_id).cloned().unwrap_or_default(),
                product_roles: product_roles_by_user.get(&user_id).cloned().unwrap_or_default(),
                invited_at: r.get("invited_at"),
                joined_at: r.get("joined_at"),
            }
        })
        .collect();

    TeamResponse {
        id: team_row.get("id"),
        name: team_row.get("name"),
        description: team_row.get("description"),
        purpose: team_row.get("purpose"),
        avatar_url: team_row.get("avatar_url"),
        owner: row_to_team_user_ref(
            team_row, "owner_id", "owner_username", "owner_email",
            "owner_first_name", "owner_last_name", "owner_avatar_url",
        ),
        leader: row_to_team_user_ref(
            team_row, "leader_id", "leader_username", "leader_email",
            "leader_first_name", "leader_last_name", "leader_avatar_url",
        ),
        members,
        created_at: team_row.get("created_at"),
        updated_at: team_row.get("updated_at"),
    }
}

fn row_to_team_role(row: &tokio_postgres::Row) -> TeamRoleResponse {
    TeamRoleResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn row_to_team_member_row(row: &tokio_postgres::Row) -> TeamMemberRow {
    TeamMemberRow {
        id: row.get("id"),
        team_id: row.get("team_id"),
        user_id: row.get("user_id"),
        status: row.get("status"),
        invite_token_expires_at: row.get("invite_token_expires_at"),
        invited_at: row.get("invited_at"),
        joined_at: row.get("joined_at"),
    }
}

// ── Admin per-user access queries ─────────────────────────────────────────────

/// `GET /admin/users/{id}/subscriptions` — all subscriptions for one user.
pub async fn admin_list_user_subscriptions(
    pool: &Pool,
    user_id: Uuid,
) -> Result<Vec<AdminSubscription>, AppError> {
    let client = pool.get().await?;
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
             WHERE s.user_id = $1
             ORDER BY p.name, s.created_at DESC",
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_admin_subscription).collect())
}

/// `GET /admin/users/{id}/teams` — teams a user belongs to, with enabled products per team.
pub async fn admin_list_user_teams(
    pool: &Pool,
    user_id: Uuid,
) -> Result<Vec<UserTeamAccess>, AppError> {
    let client = pool.get().await?;

    // Fetch the user's active team memberships.
    // Role is derived from teams.owner_id / leader_id — team_members has no role column.
    let team_rows = client
        .query(
            "SELECT t.id, t.name, t.description, t.avatar_url,
                    CASE
                        WHEN t.owner_id  = $1 THEN 'owner'
                        WHEN t.leader_id = $1 THEN 'leader'
                        ELSE 'member'
                    END AS member_role
             FROM teams t
             JOIN team_members tm ON tm.team_id = t.id
             WHERE tm.user_id = $1 AND tm.status = 'active'
             ORDER BY t.name",
            &[&user_id],
        )
        .await?;

    if team_rows.is_empty() {
        return Ok(vec![]);
    }

    let team_ids: Vec<Uuid> = team_rows.iter().map(|r| r.get("id")).collect();

    // Fetch all product grants for those teams in one query.
    let product_rows = client
        .query(
            "SELECT tpa.team_id, tpa.product_slug, p.name AS product_name
             FROM team_product_access tpa
             JOIN products p ON p.slug = tpa.product_slug
             WHERE tpa.team_id = ANY($1)
             ORDER BY p.name",
            &[&team_ids],
        )
        .await?;

    // Group products by team_id.
    let mut products_by_team: HashMap<Uuid, Vec<TeamProductRef>> = HashMap::new();
    for row in &product_rows {
        let tid: Uuid = row.get("team_id");
        products_by_team
            .entry(tid)
            .or_default()
            .push(TeamProductRef {
                slug: row.get("product_slug"),
                name: row.get("product_name"),
            });
    }

    let result = team_rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            UserTeamAccess {
                id,
                name: r.get("name"),
                description: r.get("description"),
                avatar_url: r.get("avatar_url"),
                member_role: r.get("member_role"),
                products: products_by_team.remove(&id).unwrap_or_default(),
            }
        })
        .collect();

    Ok(result)
}
