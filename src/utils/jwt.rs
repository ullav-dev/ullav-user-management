use crate::errors::AppError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims embedded in the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user's UUID as a string.
    pub sub: String,
    /// Issued-at epoch seconds.
    pub iat: i64,
    /// Expiry epoch seconds.
    pub exp: i64,
    /// Roles assigned to the user.
    pub roles: Vec<String>,
    /// Permissions granted to the user (union of all role permissions).
    pub permissions: Vec<String>,
}

/// Create a signed JWT for the given user id.
pub fn create_jwt(
    user_id: Uuid,
    secret: &str,
    ttl_hours: i64,
    roles: Vec<String>,
    permissions: Vec<String>,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::hours(ttl_hours)).timestamp(),
        roles,
        permissions,
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
