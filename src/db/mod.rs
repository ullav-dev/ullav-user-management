use crate::errors::AppError;
use crate::models::{PasswordResetToken, Subscription, User};
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
/// Returns a list of Subscriptions used when building JWT claims (Phase 4).
#[allow(dead_code)]
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
