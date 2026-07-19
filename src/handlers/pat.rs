//! Personal access tokens — user-issued credentials for git-over-HTTPS Basic
//! auth (lagan) and other non-interactive CLI use. See
//! `migrations/026_personal_access_tokens.sql` and `db::pat` for the storage
//! model, and `utils::jwt::GitAccessClaims` for the token this exchanges into.

use crate::{
    db,
    errors::AppError,
    middleware::auth::claims_from_req,
    models::{validate_git_scopes, CreatePatRequest, ExchangeGitCredentialRequest, GitAccessTokenResponse},
    utils::{
        check_service_secret,
        jwt::create_git_access_jwt,
        token::{secure_hex_token, sha256_hex},
    },
    AppState,
};
use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};
use uuid::Uuid;

/// Token prefix identifying this as a lagan personal access token (mirrors the
/// GitHub/GitLab convention of a recognisable prefix so leaked tokens are
/// greppable in logs/scans).
const TOKEN_PREFIX: &str = "lgn_pat_";
/// How long a JWT minted by `/pat/exchange` lives. Short — this mint happens
/// on every git-over-HTTPS request during a clone/push, and the credential
/// (the PAT itself) is what's actually long-lived and independently revocable.
const EXCHANGE_TOKEN_TTL_MINUTES: i64 = 15;
/// `client_id` stamped into the minted `GitAccessClaims` — identifies the
/// credential type in audit logs, not a real OAuth2 client (see the
/// `GitAccessClaims` doc comment for why this field exists at all).
const CLIENT_ID: &str = "lagan-pat";

/// `POST /pat` — create a new personal access token. The raw token is
/// returned once in the response body and never stored or retrievable again.
#[post("/pat")]
pub async fn create_pat(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreatePatRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    let scopes = validate_git_scopes(body.scopes.clone()).map_err(AppError::Validation)?;
    if let Some(days) = body.expires_in_days {
        if days <= 0 {
            return Err(AppError::Validation("expires_in_days must be positive".into()));
        }
    }

    let raw = secure_hex_token(32);
    let token = format!("{TOKEN_PREFIX}{raw}");
    let token_hash = sha256_hex(&token);
    let token_prefix: String = token.chars().take(TOKEN_PREFIX.len() + 4).collect();

    let summary = db::pat::create_pat(
        &state.pool,
        user_id,
        body.name.trim(),
        &token_hash,
        &token_prefix,
        &scopes,
        body.expires_in_days,
    )
    .await?;

    Ok(HttpResponse::Created().json(crate::models::CreatePatResponse {
        id: summary.id,
        token,
        name: summary.name,
        token_prefix: summary.token_prefix,
        scopes: summary.scopes,
        expires_at: summary.expires_at,
        created_at: summary.created_at,
    }))
}

/// `GET /pat` — list the caller's own PATs (never the raw token or its hash).
#[get("/pat")]
pub async fn list_pats(state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let pats = db::pat::list_pats(&state.pool, user_id).await?;
    Ok(HttpResponse::Ok().json(pats))
}

/// `DELETE /pat/{id}` — revoke one of the caller's own PATs.
#[delete("/pat/{id}")]
pub async fn revoke_pat(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    db::pat::revoke_pat(&state.pool, user_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /pat/exchange` — internal endpoint called by lagan-server (or any
/// other service accepting git-over-HTTPS credentials), never by a human
/// directly. The PAT itself *is* the credential — no `Authorization` bearer
/// header is involved — so this is registered in the unauthenticated route
/// group and instead gated by an optional shared-secret header
/// (`X-Git-Service-Secret`, checked against `GIT_SERVICE_SHARED_SECRET`) to
/// keep it from being a fully open oracle for "is this token valid" on a
/// publicly reachable listener.
///
/// Resolves the PAT, mints a short-lived `GitAccessClaims` JWT bound to the
/// caller-supplied `resource` (RFC 8707 audience), and returns it. The caller
/// is expected to cache the result for a few minutes keyed by the PAT's hash
/// rather than calling this on every single git-protocol request in a
/// clone/push — see the `lagan-server` design notes for that caching layer.
#[post("/pat/exchange")]
pub async fn exchange(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ExchangeGitCredentialRequest>,
) -> Result<HttpResponse, AppError> {
    check_service_secret(
        &state.git_service_shared_secret,
        req.headers().get("X-Git-Service-Secret").and_then(|v| v.to_str().ok()),
    )?;

    if body.resource.trim().is_empty() {
        return Err(AppError::Validation("resource is required (RFC 8707)".into()));
    }

    let token_hash = sha256_hex(&body.credential);
    let resolved = db::pat::get_active_pat_by_hash(&state.pool, &token_hash).await?;
    db::pat::touch_pat_last_used(&state.pool, resolved.id).await;

    let user = db::get_user_by_id(&state.pool, resolved.user_id).await?;
    let (roles, _permissions, subscriptions, teams) =
        crate::utils::jwt::build_identity_claims(&state.pool, resolved.user_id).await?;

    let signing_key = state.oauth2_keys.read().await.primary_key().clone();
    let access_token = create_git_access_jwt(
        user.id,
        user.username,
        &state.oauth2_issuer,
        &body.resource,
        CLIENT_ID,
        EXCHANGE_TOKEN_TTL_MINUTES,
        &resolved.scopes.join(" "),
        roles,
        subscriptions,
        teams,
        &signing_key,
    )?;

    Ok(HttpResponse::Ok().json(GitAccessTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: EXCHANGE_TOKEN_TTL_MINUTES * 60,
    }))
}

/// `GET /admin/git-credentials/pats` — audit view of every PAT across every
/// user. Requires `git_credentials:manage`. Registered under the
/// `/admin/git-credentials` scope in `main.rs`, hence the relative path here.
#[get("/pats")]
pub async fn admin_list_pats(state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let pats = db::pat::admin_list_all_pats(&state.pool).await?;
    Ok(HttpResponse::Ok().json(pats))
}
