use crate::errors::AppError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Per-product subscription data embedded in the JWT.
///
/// Keyed by product slug (e.g. `"clann"`) in the `subscriptions` claim map.
/// Downstream services read this to enforce plan limits without a DB call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionClaim {
    /// Plan name: "individual", "family", "professional", "enterprise".
    pub tier: String,
    /// Subscription status: "active", "trialing", "past_due", "cancelled".
    pub status: String,
    /// Number of seats — present for multi-seat plans (Family/Team).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat_count: Option<i16>,
}

/// Per-team data embedded in the JWT.
///
/// Keyed by team UUID string in the `teams` claim map.
/// Only active memberships are included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamClaim {
    pub name: String,
    /// Positional role: `"owner"`, `"leader"`, or `"member"`.
    pub role: String,
    /// Custom team roles assigned to this member (e.g. `"Approver"`, `"Editor"`).
    /// Downstream services use these names to gate domain-specific functionality.
    /// Defaults to an empty vec so tokens issued before this field was added still decode.
    #[serde(default)]
    pub team_roles: Vec<String>,
}

/// JWT claims embedded in the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user's UUID as a string.
    pub sub: String,
    /// Issued-at epoch seconds.
    pub iat: i64,
    /// Expiry epoch seconds.
    pub exp: i64,
    /// The user's login username — included so downstream services can display
    /// human-readable attribution without an extra lookup.
    /// Defaults to empty string so tokens issued before this field was added still decode.
    #[serde(default)]
    pub username: String,
    /// Roles assigned to the user.
    pub roles: Vec<String>,
    /// Permissions granted to the user (union of all role permissions).
    pub permissions: Vec<String>,
    /// Active subscriptions keyed by product slug.
    /// Defaults to an empty map so tokens issued before subscriptions were added still decode.
    #[serde(default)]
    pub subscriptions: HashMap<String, SubscriptionClaim>,
    /// Active team memberships keyed by team UUID string.
    /// Defaults to an empty map so tokens issued before teams were added still decode.
    #[serde(default)]
    pub teams: HashMap<String, TeamClaim>,
}

/// Create a signed JWT for the given user id.
pub fn create_jwt(
    user_id: Uuid,
    username: String,
    secret: &str,
    ttl_hours: i64,
    roles: Vec<String>,
    permissions: Vec<String>,
    subscriptions: HashMap<String, SubscriptionClaim>,
    teams: HashMap<String, TeamClaim>,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::hours(ttl_hours)).timestamp(),
        username,
        roles,
        permissions,
        subscriptions,
        teams,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Jwt(e.to_string()))
}

/// Decode and validate a JWT, returning the embedded claims.
pub fn decode_jwt(token: &str, secret: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| AppError::Jwt(e.to_string()))
}
