use serde::{Deserialize, Deserializer, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

// ── Admin models ──────────────────────────────────────────────────────────────

/// User with their assigned roles — returned by admin endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct UserWithRoles {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub is_active: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
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
/// Optional string fields use `Option<Option<String>>` so callers can distinguish
/// "omit (no change)" from `null` (clear the field).
#[derive(Debug, Deserialize)]
pub struct AdminUpdateUserRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub is_active: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    pub first_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    pub last_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    pub avatar_url: Option<Option<String>>,
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

/// Deserializer that maps an absent field to `None` and a present field
/// (including JSON `null`) to `Some(Option<String>)`. Allows PATCH endpoints to
/// distinguish "omit → no change" from `null → clear the field`.
pub fn deserialize_nullable_string<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(Option::<String>::deserialize(d)?))
}

/// Same as [`deserialize_nullable_string`], but for a nullable UUID field —
/// used by `AdminUpdateTeamRequest.organization_id` so a PATCH can distinguish
/// "omit → no change" from `null → unassign the team's organization".
pub fn deserialize_nullable_uuid<'de, D>(d: D) -> Result<Option<Option<Uuid>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(Option::<Uuid>::deserialize(d)?))
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
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
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
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
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
            first_name: u.first_name,
            last_name: u.last_name,
            avatar_url: u.avatar_url,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// Request body for `PATCH /users/me`.
/// All fields are optional. `avatar_url` uses `Option<Option<String>>` so that
/// `null` (clear) can be distinguished from absent (no change).
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    pub avatar_url: Option<Option<String>>,
}

/// Request body for `POST /admin/users` — create a pre-confirmed, active user.
#[derive(Debug, Deserialize)]
pub struct AdminCreateUserRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Request body for creating a new user.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
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

// ── Teams ────────────────────────────────────────────────────────────────────

/// Minimal user info embedded in team API responses.
#[derive(Debug, Clone, Serialize)]
pub struct TeamUserRef {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// A custom role defined within a team.
#[derive(Debug, Clone, Serialize)]
pub struct TeamRoleResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// True for the built-in "All" role (every team member) — cannot be deleted or
    /// manually unassigned, though it can be renamed.
    pub is_all: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A team member as returned by API responses.
#[derive(Debug, Clone, Serialize)]
pub struct TeamMemberResponse {
    pub id: Uuid,
    pub user: TeamUserRef,
    /// `invited` | `active` | `inactive`
    pub status: String,
    /// `owner` | `leader` | `member` — derived from the team's owner_id / leader_id columns.
    pub role: String,
    /// Custom team roles assigned to this member.
    pub team_roles: Vec<TeamRoleResponse>,
    /// Product-specific roles assigned to this member (e.g. `"cunav"` → `"support"`).
    pub product_roles: HashMap<String, String>,
    pub invited_at: DateTime<Utc>,
    pub joined_at: Option<DateTime<Utc>>,
}

/// Full team representation including member list.
#[derive(Debug, Clone, Serialize)]
pub struct TeamResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub avatar_url: Option<String>,
    pub organization_id: Option<Uuid>,
    pub is_support_team: bool,
    pub owner: TeamUserRef,
    pub leader: TeamUserRef,
    pub members: Vec<TeamMemberResponse>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Lightweight team summary used in list endpoints (no member list).
#[derive(Debug, Clone, Serialize)]
pub struct TeamSummary {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub organization_id: Option<Uuid>,
    pub is_support_team: bool,
    pub avatar_url: Option<String>,
    pub owner: TeamUserRef,
    pub leader: TeamUserRef,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Minimal team lookup by slug — used by lagan-server to resolve
/// `{team-slug}/{repo-slug}` clone URLs to a team UUID.
#[derive(Debug, Clone, Serialize)]
pub struct TeamLookup {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
}

/// Paginated list of teams returned by admin list endpoint.
#[derive(Debug, Serialize)]
pub struct TeamsPage {
    pub teams: Vec<TeamSummary>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

/// Internal DB row for a team_members record — used for token lookups and auth checks.
#[derive(Debug, Clone)]
pub struct TeamMemberRow {
    pub id: Uuid,
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub status: String,
    pub invite_token_expires_at: Option<DateTime<Utc>>,
    pub invited_at: DateTime<Utc>,
    pub joined_at: Option<DateTime<Utc>>,
}

/// Request body for creating a team (caller becomes the owner).
#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub avatar_url: Option<String>,
}

/// Request body for partially updating a team (owner/leader).
#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub avatar_url: Option<String>,
    /// Only the current owner may change the leader.
    pub leader_id: Option<Uuid>,
}

/// Request body for inviting a user to a team by email.
#[derive(Debug, Deserialize)]
pub struct InviteTeamMemberRequest {
    pub email: String,
    /// Frontend base URL used to build the invitation link in the email.
    pub app_url: Option<String>,
}

/// Request body for resending a team invitation.
#[derive(Debug, Deserialize)]
pub struct ResendInviteRequest {
    pub app_url: Option<String>,
}

/// Request body for creating a team role.
#[derive(Debug, Deserialize)]
pub struct CreateTeamRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

/// Request body for partially updating a team role.
#[derive(Debug, Deserialize)]
pub struct UpdateTeamRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Admin request body for directly adding an active member (bypasses invite flow).
#[derive(Debug, Deserialize)]
pub struct AdminAddTeamMemberRequest {
    pub user_id: Uuid,
}

/// A product that has been enabled for a team.
#[derive(Debug, Clone, Serialize)]
pub struct TeamProductAccessResponse {
    pub product_slug: String,
    pub product_name: String,
    pub granted_at: DateTime<Utc>,
    pub granted_by_username: Option<String>,
}

/// A product enabled for a team — minimal slug+name for embedding in per-user responses.
#[derive(Debug, Clone, Serialize)]
pub struct TeamProductRef {
    pub slug: String,
    pub name: String,
}

/// A team a user belongs to, with the products that team has enabled.
/// Used by `GET /admin/users/{id}/teams`.
#[derive(Debug, Serialize)]
pub struct UserTeamAccess {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    /// The user's role in this team: "owner", "leader", or "member".
    pub member_role: String,
    pub products: Vec<TeamProductRef>,
}

/// Request body for assigning or updating a product role for a team member.
#[derive(Debug, Deserialize)]
pub struct AssignProductRoleRequest {
    pub role: String,
}

/// Admin request body for creating a team with an explicit owner.
#[derive(Debug, Deserialize)]
pub struct AdminCreateTeamRequest {
    pub name: String,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub avatar_url: Option<String>,
    pub owner_id: Uuid,
}

/// Admin request body for partially updating a team.
#[derive(Debug, Deserialize)]
pub struct AdminUpdateTeamRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub avatar_url: Option<String>,
    pub owner_id: Option<Uuid>,
    pub leader_id: Option<Uuid>,
    /// Omit to leave unchanged; `null` unassigns the team's organization; a UUID assigns/reassigns it.
    #[serde(default, deserialize_with = "deserialize_nullable_uuid")]
    pub organization_id: Option<Option<Uuid>>,
    /// Omit to leave unchanged. Setting `true` unsets any other team's flag within
    /// the same organization_id (NULL included) first — see `admin_update_team`.
    pub is_support_team: Option<bool>,
}

/// An organization — a new tenant boundary that owns Teams. Fully optional:
/// a team with no organization behaves exactly as it always has.
#[derive(Debug, Clone, Serialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AdminCreateOrganizationRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminUpdateOrganizationRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub description: Option<String>,
}

// ── Password reset tokens ─────────────────────────────────────────────────────

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

// ── Git credential scopes (shared by PATs and SSH keys) ──────────────────────

/// The only scopes a git credential (PAT or SSH key) may be granted. Enforced
/// on creation — anything else is rejected with `AppError::Validation`.
pub const VALID_GIT_SCOPES: &[&str] = &["repo:read", "repo:write"];

/// Validate a requested scope list against `VALID_GIT_SCOPES`, defaulting to
/// full read+write access when none is supplied (the credential is then only
/// as powerful as the account itself — restricting it further is opt-in).
pub fn validate_git_scopes(requested: Option<Vec<String>>) -> Result<Vec<String>, String> {
    let scopes = requested.unwrap_or_else(|| {
        VALID_GIT_SCOPES.iter().map(|s| s.to_string()).collect()
    });
    if scopes.is_empty() {
        return Err("scopes must not be empty — omit the field entirely for the default (full access)".into());
    }
    for s in &scopes {
        if !VALID_GIT_SCOPES.contains(&s.as_str()) {
            return Err(format!(
                "invalid scope {s:?} — must be one of {VALID_GIT_SCOPES:?}"
            ));
        }
    }
    Ok(scopes)
}

// ── Personal access tokens (git-over-HTTPS) ───────────────────────────────────

/// Request body for `POST /pat`.
#[derive(Debug, Deserialize)]
pub struct CreatePatRequest {
    pub name: String,
    /// Defaults to full access (`["repo:read", "repo:write"]`) when omitted.
    pub scopes: Option<Vec<String>>,
    /// `None` = no expiry (still revocable at any time via `DELETE /pat/{id}`).
    pub expires_in_days: Option<i64>,
}

/// A PAT as returned by list/audit endpoints — never includes the raw token
/// or its hash.
#[derive(Debug, Clone, Serialize)]
pub struct PatSummary {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Response for `POST /pat` — the only time the raw token is ever returned.
#[derive(Debug, Serialize)]
pub struct CreatePatResponse {
    pub id: Uuid,
    /// Shown once. Store it now — it cannot be retrieved again.
    pub token: String,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Admin audit view of a PAT — owner identity included, secret material never is.
#[derive(Debug, Serialize)]
pub struct AdminPatSummary {
    pub id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

// ── SSH public keys (git-over-SSH) ────────────────────────────────────────────

/// Request body for `POST /ssh-keys`.
#[derive(Debug, Deserialize)]
pub struct CreateSshKeyRequest {
    pub name: String,
    /// Full OpenSSH public key line, e.g. `"ssh-ed25519 AAAA... comment"`.
    pub public_key: String,
    /// Defaults to full access (`["repo:read", "repo:write"]`) when omitted.
    pub scopes: Option<Vec<String>>,
}

/// An SSH key as returned by list/audit endpoints — the public key material
/// itself is not secret and is included, but ownership/ACL data never crosses
/// into anything resembling a private key (which this table never stores).
#[derive(Debug, Clone, Serialize)]
pub struct SshKeySummary {
    pub id: Uuid,
    pub name: String,
    pub fingerprint: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Admin audit view of an SSH key — owner identity included.
#[derive(Debug, Serialize)]
pub struct AdminSshKeySummary {
    pub id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub name: String,
    pub fingerprint: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

// ── Git credential exchange (internal — called by lagan-server, not humans) ──

/// Request body for `POST /pat/exchange` and `POST /ssh-keys/resolve`.
///
/// `resource` is an RFC 8707 resource indicator — the canonical URI of the
/// lagan-server instance that will validate the minted token, matching the
/// convention already used by the OAuth2 `resource` parameter elsewhere in
/// this service. `credential` is the raw PAT string or, for the SSH variant,
/// the key's `SHA256:...` fingerprint.
#[derive(Debug, Deserialize)]
pub struct ExchangeGitCredentialRequest {
    pub credential: String,
    pub resource: String,
}

/// Response for both exchange endpoints.
#[derive(Debug, Serialize)]
pub struct GitAccessTokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}
