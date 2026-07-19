//! SSH public keys — user-registered credentials for git-over-SSH access
//! (lagan). See `migrations/027_user_ssh_keys.sql` and `db::ssh_keys` for the
//! storage model, and `utils::jwt::GitAccessClaims` for the token this
//! exchanges into. Mirrors `handlers::pat` closely — the two credential types
//! share the same scope model and exchange-to-JWT flow, differing only in
//! what identifies the credential (a hashed secret vs. a public key
//! fingerprint) and how it's presented (Basic auth password vs. SSH
//! publickey auth).

use crate::{
    db,
    errors::AppError,
    middleware::auth::claims_from_req,
    models::{validate_git_scopes, CreateSshKeyRequest, ExchangeGitCredentialRequest, GitAccessTokenResponse},
    utils::{check_service_secret, jwt::create_git_access_jwt},
    AppState,
};
use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};
use ssh_key::{HashAlg, PublicKey};
use uuid::Uuid;

/// How long a JWT minted by `/ssh-keys/resolve` lives — same rationale as
/// `handlers::pat::EXCHANGE_TOKEN_TTL_MINUTES`: this mint happens once per SSH
/// connection (cached for the connection's lifetime by the caller), not once
/// per channel, so a short TTL doesn't force excessive re-minting.
const EXCHANGE_TOKEN_TTL_MINUTES: i64 = 15;
/// `client_id` stamped into the minted `GitAccessClaims` — see
/// `handlers::pat::CLIENT_ID` for why this field exists at all.
const CLIENT_ID: &str = "lagan-ssh";

/// Parse an OpenSSH public key line and compute its `SHA256:...` fingerprint
/// (the same format `ssh-keygen -lf` prints), rejecting anything that isn't a
/// well-formed public key up front rather than storing garbage that would
/// only fail later at connection time.
fn parse_and_fingerprint(public_key: &str) -> Result<String, AppError> {
    let key = PublicKey::from_openssh(public_key.trim())
        .map_err(|e| AppError::Validation(format!("invalid SSH public key: {e}")))?;
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
}

/// `POST /ssh-keys` — register a new SSH public key for the caller.
#[post("/ssh-keys")]
pub async fn create_ssh_key(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateSshKeyRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    let scopes = validate_git_scopes(body.scopes.clone()).map_err(AppError::Validation)?;
    let fingerprint = parse_and_fingerprint(&body.public_key)?;

    let summary = db::ssh_keys::create_ssh_key(
        &state.pool,
        user_id,
        body.name.trim(),
        body.public_key.trim(),
        &fingerprint,
        &scopes,
    )
    .await?;

    Ok(HttpResponse::Created().json(summary))
}

/// `GET /ssh-keys` — list the caller's own registered SSH keys.
#[get("/ssh-keys")]
pub async fn list_ssh_keys(state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let keys = db::ssh_keys::list_ssh_keys(&state.pool, user_id).await?;
    Ok(HttpResponse::Ok().json(keys))
}

/// `DELETE /ssh-keys/{id}` — remove one of the caller's own SSH keys.
#[delete("/ssh-keys/{id}")]
pub async fn delete_ssh_key(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    db::ssh_keys::delete_ssh_key(&state.pool, user_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /ssh-keys/resolve` — internal endpoint called by lagan-server's SSH
/// server at connection-auth time, never by a human directly. See
/// `handlers::pat::exchange` for the shared-secret gating rationale — the
/// only difference here is the credential is a fingerprint the caller already
/// computed from the offered SSH key, not a bearer secret.
#[post("/ssh-keys/resolve")]
pub async fn resolve(
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

    let resolved = db::ssh_keys::get_ssh_key_by_fingerprint(&state.pool, &body.credential).await?;
    db::ssh_keys::touch_ssh_key_last_used(&state.pool, resolved.id).await;

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

/// `GET /admin/git-credentials/ssh-keys` — audit view of every SSH key across
/// every user. Requires `git_credentials:manage`. Registered under the
/// `/admin/git-credentials` scope in `main.rs`, hence the relative path here.
#[get("/ssh-keys")]
pub async fn admin_list_ssh_keys(state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let keys = db::ssh_keys::admin_list_all_ssh_keys(&state.pool).await?;
    Ok(HttpResponse::Ok().json(keys))
}
