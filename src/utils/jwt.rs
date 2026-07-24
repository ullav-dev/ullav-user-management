use crate::errors::AppError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
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
    /// URL-safe unique slug — lets downstream services (lagan) build
    /// `{team-slug}/{repo-slug}` clone URLs without an extra lookup.
    /// Defaults to empty string so tokens issued before this field was added
    /// still decode.
    #[serde(default)]
    pub slug: String,
    /// Positional role: `"owner"`, `"leader"`, or `"member"`.
    pub role: String,
    /// Custom team roles assigned to this member (e.g. `"Approver"`, `"Editor"`).
    /// Downstream services use these names to gate domain-specific functionality.
    /// Defaults to an empty vec so tokens issued before this field was added still decode.
    #[serde(default)]
    pub team_roles: Vec<String>,
    /// Product-specific access roles for this member within the team.
    /// Key: product slug (e.g. `"obair"`), value: role (e.g. `"admin"`, `"lead"`, `"member"`).
    /// Defaults to an empty map so tokens issued before this field was added still decode.
    #[serde(default)]
    pub product_roles: HashMap<String, String>,
    /// Product slugs that this team has enabled at the team level (from `team_product_access`).
    /// Downstream services use this to gate access to a product for all team members.
    /// A user may only access a product-gated service if they are a member of at least one
    /// team that has the product enabled here.
    /// Defaults to an empty vec so tokens issued before this field was added still decode.
    #[serde(default)]
    pub products: Vec<String>,
    /// The organization this team belongs to, if any (most teams don't, yet —
    /// organizations are a new, optional concept). `None` for org-less teams
    /// and for tokens issued before organizations existed. Name/slug are
    /// denormalized alongside the id (matching how the team's own name/slug
    /// are denormalized here) so a downstream service can display them
    /// without an extra lookup — deliberately *not* a separate top-level
    /// `organizations` claim, since every consumer that cares about a team's
    /// organization already has the `TeamClaim` in hand.
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub organization_name: Option<String>,
    #[serde(default)]
    pub organization_slug: Option<String>,
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
    /// Defaults to empty so tokens without this field (e.g. MCP OAuth2 access tokens,
    /// which carry `sub`/`aud`/`scope` but no role/permission data) still decode —
    /// they're identified but hold no roles, so permission-gated routes still 403 them.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Permissions granted to the user (union of all role permissions).
    /// Defaults to empty for the same reason as `roles`.
    #[serde(default)]
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

/// Fetch and assemble a user's roles, permissions, subscriptions, and active team
/// memberships — shared by `/auth/login` and MCP OAuth2 token minting so both
/// issue tokens describing the same identity data.
pub async fn build_identity_claims(
    pool: &deadpool_postgres::Pool,
    user_id: Uuid,
) -> Result<(Vec<String>, Vec<String>, HashMap<String, SubscriptionClaim>, HashMap<String, TeamClaim>), AppError> {
    let (roles, mut permissions) = crate::db::get_user_roles_and_permissions(pool, user_id).await?;

    // Build subscription claims from the DB — keyed by product slug.
    let raw_subs = crate::db::get_all_user_subscriptions(pool, user_id).await?;
    let subscriptions: HashMap<String, SubscriptionClaim> = raw_subs
        .into_iter()
        .map(|s| {
            let claim = SubscriptionClaim {
                tier: s.plan.clone(),
                status: s.status.clone(),
                seat_count: if s.seat_count > 1 { Some(s.seat_count) } else { None },
            };
            (s.product_slug, claim)
        })
        .collect();

    // Grant teams:create to users with an active/trialing Family, Professional, or Enterprise
    // Clann subscription — without requiring the admin role to manually assign the permission.
    let clann_eligible = subscriptions.get("clann").map_or(false, |s| {
        matches!(s.status.as_str(), "active" | "trialing")
            && matches!(s.tier.as_str(), "family" | "professional" | "enterprise")
    });
    if clann_eligible && !permissions.contains(&"teams:create".to_string()) {
        permissions.push("teams:create".to_string());
        permissions.sort();
    }

    // Build team claims — only active memberships, keyed by team UUID string.
    let raw_teams = crate::db::get_user_active_teams(pool, user_id).await?;
    let teams: HashMap<String, TeamClaim> = raw_teams
        .into_iter()
        .map(|t| {
            let (organization_id, organization_name, organization_slug) = match t.organization {
                Some(org) => (Some(org.id), Some(org.name), Some(org.slug)),
                None => (None, None, None),
            };
            (t.team_id, TeamClaim {
                name: t.name,
                slug: t.slug,
                role: t.role,
                team_roles: t.team_roles,
                product_roles: t.product_roles,
                products: t.products,
                organization_id,
                organization_name,
                organization_slug,
            })
        })
        .collect();

    Ok((roles, permissions, subscriptions, teams))
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

/// Create a signed RS256 JWT for the given user (fleet migration — replaces HS256).
pub fn create_jwt_rs256(
    user_id:       Uuid,
    username:      String,
    issuer:        &str,
    ttl_hours:     i64,
    roles:         Vec<String>,
    permissions:   Vec<String>,
    subscriptions: HashMap<String, SubscriptionClaim>,
    teams:         HashMap<String, TeamClaim>,
    key:           &crate::utils::rs256::RsaKeyPair,
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

    // Embed 'iss' alongside Claims via a thin wrapper so validators can check it.
    #[derive(Serialize)]
    struct WithIss<'a> {
        iss: &'a str,
        #[serde(flatten)]
        inner: &'a Claims,
    }

    encode(
        &key.jwt_header(),
        &WithIss { iss: issuer, inner: &claims },
        key.encoding_key(),
    )
    .map_err(|e| AppError::Jwt(e.to_string()))
}

/// Claims for a short-lived JWT exchanged from a git credential (a personal
/// access token or an SSH public key — see `handlers::pat`/`handlers::ssh_keys`).
///
/// Deliberately shaped identically to `ullav_mcp_auth::validator::McpClaims`
/// (`iss`/`sub`/`aud`/`iat`/`exp`/`scope`/`client_id`/`username`/`roles`/
/// `subscriptions`/`teams`) rather than reusing plain `Claims`, so that any
/// service already depending on `ullav-mcp-auth` (as `awe-server` does) can
/// validate this token with the exact same `TokenValidator::validate()` call
/// it uses for MCP OAuth2 tokens — including the `aud` check, which plain
/// `Claims`-shaped tokens never carry. `client_id` is set to a fixed constant
/// identifying the credential type (`"lagan-pat"` / `"lagan-ssh"`), not a real
/// OAuth2 client — it exists purely so the JSON shape matches `McpClaims` and
/// downstream audit logs can distinguish which credential minted the token.
///
/// `scope` carries the *credential's* own scope restriction (space-separated,
/// e.g. `"repo:read"`), which callers must enforce in addition to — not
/// instead of — the account's normal team/role permissions: a read-only PAT
/// must not grant write access even if the account otherwise could.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitAccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub scope: String,
    pub client_id: String,
    pub username: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub subscriptions: HashMap<String, SubscriptionClaim>,
    #[serde(default)]
    pub teams: HashMap<String, TeamClaim>,
}

/// Mint a short-lived `GitAccessClaims` token for a resolved git credential.
///
/// `resource` is the caller-supplied audience (RFC 8707 resource indicator,
/// same convention as the OAuth2 `resource` parameter) — the canonical URI of
/// the lagan-server instance that will validate this token, so a token minted
/// for one resource server can't be replayed against another.
#[allow(clippy::too_many_arguments)]
pub fn create_git_access_jwt(
    user_id: Uuid,
    username: String,
    issuer: &str,
    resource: &str,
    client_id: &str,
    ttl_minutes: i64,
    scope: &str,
    roles: Vec<String>,
    subscriptions: HashMap<String, SubscriptionClaim>,
    teams: HashMap<String, TeamClaim>,
    key: &crate::utils::rs256::RsaKeyPair,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = GitAccessClaims {
        iss: issuer.to_owned(),
        sub: user_id.to_string(),
        aud: resource.to_owned(),
        iat: now.timestamp(),
        exp: (now + Duration::minutes(ttl_minutes)).timestamp(),
        scope: scope.to_owned(),
        client_id: client_id.to_owned(),
        username,
        roles,
        subscriptions,
        teams,
    };
    encode(&key.jwt_header(), &claims, key.encoding_key())
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

/// Decode and validate an RS256 JWT, trying each key in the store (supports key rotation).
/// Returns the claims from the first key that successfully validates the token.
pub fn decode_jwt_rs256(
    token: &str,
    keys: &[crate::utils::rs256::RsaKeyPair],
) -> Result<Claims, AppError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    // This function validates both plain login tokens (no `aud` claim) and MCP OAuth2
    // access tokens (audience-bound to a specific resource server, e.g. an awe-server
    // MCP endpoint). `Validation::new` defaults `validate_aud` to true, and this crate
    // version treats "token has an aud claim, validator has none configured" as an
    // InvalidAudience failure rather than skipping the check — which silently rejected
    // every MCP token here. Audience isn't this function's concern: whoever forwards a
    // token to a specific resource server is responsible for checking it's the intended
    // audience, same as ullav_mcp_auth::TokenValidator::validate_as does for this exact
    // "service-API token with no audience check" case.
    validation.validate_aud = false;

    let mut last_err = None;
    for key in keys {
        let decoding_key = key.decoding_key()?;
        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(data) => return Ok(data.claims),
            Err(e) => last_err = Some(e),
        }
    }
    // Temporary diagnostic: the middleware collapses every failure mode (bad
    // signature, expired, wrong claims shape, wrong algorithm) into the same
    // generic 401, which made a real client-reported failure impossible to
    // triage from logs alone. Logging the concrete jsonwebtoken error here
    // (kind, not the token itself) is safe and removable once diagnosed.
    if let Some(e) = last_err {
        log::warn!("decode_jwt_rs256: all {} key(s) failed, last error: {:?}", keys.len(), e.kind());
    } else {
        log::warn!("decode_jwt_rs256: no active keys available to try");
    }
    Err(AppError::InvalidToken)
}
