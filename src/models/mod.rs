use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A user account stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing)]
    pub confirmation_token: Option<String>,
    #[serde(skip_serializing)]
    pub confirmation_token_expires_at: Option<DateTime<Utc>>,
}

/// Public view of a user (no sensitive fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            username: u.username,
            is_active: u.is_active,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// Request body for creating a new user.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    /// Base URL of the calling application, used to build the confirmation-email link.
    /// Must be present in `ALLOWED_APP_URLS` when that variable is configured.
    /// Ignored when `ALLOWED_APP_URLS` is not set; falls back to `APP_BASE_URL`.
    pub app_url: Option<String>,
}

/// Request body for user login.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Successful login response carrying the JWT.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserResponse,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

/// Request body for changing a user's own password.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: Option<String>,
    pub new_password: String,
}

/// Request body for initiating a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
    /// Base URL of the calling application, used to build the password-reset link.
    /// Must be present in `ALLOWED_APP_URLS` when that variable is configured.
    /// Ignored when `ALLOWED_APP_URLS` is not set; falls back to `APP_BASE_URL`.
    pub app_url: Option<String>,
}

/// Request body for confirming an email address.
#[derive(Debug, Deserialize)]
pub struct ConfirmEmailRequest {
    pub token: String,
}

/// Request body for completing a password reset.
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirm {
    pub token: String,
    pub new_password: String,
}

// ── Subscriptions ─────────────────────────────────────────────────────────────

/// A subscription row as stored in the database.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub product_id: uuid::Uuid,
    pub product_slug: String,
    pub plan: String,
    pub status: String,
    pub payment_provider: Option<String>,
    pub provider_subscription_id: Option<String>,
    pub provider_customer_id: Option<String>,
    pub seat_count: i16,
    pub trial_end: Option<chrono::DateTime<chrono::Utc>>,
    pub current_period_start: Option<chrono::DateTime<chrono::Utc>>,
    pub current_period_end: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Public API response for a subscription.
#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub id: uuid::Uuid,
    pub product: String,
    pub plan: String,
    pub status: String,
    pub seat_count: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_end: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_period_start: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_period_end: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<Subscription> for SubscriptionResponse {
    fn from(s: Subscription) -> Self {
        Self {
            id: s.id,
            product: s.product_slug,
            plan: s.plan,
            status: s.status,
            seat_count: s.seat_count,
            trial_end: s.trial_end,
            current_period_start: s.current_period_start,
            current_period_end: s.current_period_end,
            created_at: s.created_at,
        }
    }
}

/// Request body for initiating a checkout session.
#[derive(Debug, Deserialize)]
pub struct CheckoutRequest {
    pub product: String,
    pub plan: String,
    /// Payment provider: "stripe" or "paypal".
    pub provider: String,
    /// Number of seats — only relevant for the Family/Team plan.
    pub seat_count: Option<i16>,
}

/// A password-reset token row.
#[derive(Debug, Clone)]
pub struct PasswordResetToken {
    #[allow(dead_code)]
    pub id: Uuid,
    pub user_id: Uuid,
    #[allow(dead_code)]
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}
