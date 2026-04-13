use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ── Admin models ──────────────────────────────────────────────────────────────

/// User with their assigned roles — returned by admin endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct UserWithRoles {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub roles: Vec<String>,
}

/// Paginated list of users.
#[derive(Debug, Serialize)]
pub struct UsersPage {
    pub users: Vec<UserWithRoles>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

/// Admin request body for partial update of a user.
#[derive(Debug, Deserialize)]
pub struct AdminUpdateUserRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub is_active: Option<bool>,
}

/// A role together with its granted permission names.
#[derive(Debug, Serialize)]
pub struct RoleWithPermissions {
    pub name: String,
    pub permissions: Vec<String>,
}

/// Request body for creating a new role.
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
}

/// Request body for creating a new permission.
#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
}

/// A subscription row joined with its user and product — used in admin responses.
#[derive(Debug, Serialize)]
pub struct AdminSubscription {
    pub id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub product: String,
    pub product_name: String,
    pub plan: String,
    pub status: String,
    pub seat_count: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_end: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_period_start: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of subscriptions.
#[derive(Debug, Serialize)]
pub struct SubscriptionsPage {
    pub subscriptions: Vec<AdminSubscription>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

/// Admin request body for partial update of a subscription.
#[derive(Debug, Deserialize)]
pub struct AdminUpdateSubscriptionRequest {
    pub plan: Option<String>,
    pub status: Option<String>,
    pub seat_count: Option<i16>,
}

/// Admin request body for creating a subscription.
#[derive(Debug, Deserialize)]
pub struct AdminCreateSubscriptionRequest {
    pub product_slug: String,
    pub plan: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default = "default_seat_count")]
    pub seat_count: i16,
}

fn default_status() -> String { "active".into() }
fn default_seat_count() -> i16 { 1 }

/// A product row as returned by admin endpoints.
#[derive(Debug, Serialize)]
pub struct ProductResponse {
    pub slug: String,
    pub name: String,
}

/// A plan row as returned by admin endpoints.
#[derive(Debug, Serialize)]
pub struct PlanResponse {
    pub id: Uuid,
    pub product_slug: String,
    pub slug: String,
    pub name: String,
}

/// Request body for creating a new plan.
#[derive(Debug, Deserialize)]
pub struct CreatePlanRequest {
    pub product_slug: String,
    pub slug: String,
    pub name: String,
}

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

/// Response from a successful checkout session creation.
#[derive(Debug, Serialize)]
pub struct CheckoutResponse {
    /// URL to redirect the user to complete payment.
    pub url: String,
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
