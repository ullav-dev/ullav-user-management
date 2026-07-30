//! Self-service OAuth2 service clients — lets any authenticated user
//! provision their own machine-to-machine credential (client_id +
//! client_secret, `client_credentials` grant) that authenticates as
//! themselves, analogous to Personal Access Tokens (`handlers::pat`).
//!
//! This is deliberately separate from the admin-only
//! `/admin/oauth2/service-clients` endpoints (`handlers::admin`), which are
//! gated by the `oauth2:manage` permission and can provision a client against
//! *any* service-account user, with global visibility across all users.
//! These endpoints are NOT under `/admin`, require no special permission
//! beyond being authenticated, and are always scoped to the caller's own
//! `service_account_user_id` — ownership is enforced in every handler and
//! query here, the same pattern `pat.rs` uses for PATs.
//!
//! Reuses the existing service-client storage (`db::oauth2`, migration
//! `024_oauth2_service_clients.sql`) — a row in `oauth2_clients` is a
//! "service client" iff `client_secret_hash IS NOT NULL`.

use crate::{
    db,
    errors::AppError,
    middleware::auth::claims_from_req,
    utils::{password::hash_password, token::secure_hex_token},
    AppState,
};
use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateServiceClientRequest {
    pub client_name: String,
    /// Rejected if empty, or if any scope ends in ":manage" (case-insensitive)
    /// or equals "admin" — self-service clients can't request administrative
    /// scopes.
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceClientSummary {
    pub client_id: String,
    pub client_name: String,
    pub allowed_scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct CreateServiceClientResponse {
    pub client_id: String,
    /// Shown once — never retrievable again.
    pub client_secret: String,
    pub client_name: String,
    pub allowed_scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub warning: String,
}

/// Self-service clients can't request administrative scopes — those remain
/// exclusive to clients provisioned via the admin-only endpoints.
fn validate_self_service_scopes(scopes: &[String]) -> Result<(), String> {
    if scopes.is_empty() {
        return Err("allowed_scopes must not be empty".into());
    }
    for s in scopes {
        let lower = s.to_lowercase();
        if lower.ends_with(":manage") || lower == "admin" {
            return Err(format!("scope {s:?} is not available for self-service clients"));
        }
    }
    Ok(())
}

/// `POST /service-clients` — create a new self-service OAuth2 service client
/// acting as the caller. The raw client secret is returned once and never
/// stored or retrievable again (only its Argon2 hash is kept).
#[post("/service-clients")]
pub async fn create_my_service_client(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateServiceClientRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    let name = body.client_name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("client_name must not be empty".into()));
    }
    validate_self_service_scopes(&body.allowed_scopes).map_err(AppError::Validation)?;

    // client_id is generated (not user-supplied) to keep it globally unique
    // and avoid enumeration/collision across users.
    let client_id = format!(
        "usr-{}-{}",
        &user_id.simple().to_string()[..8],
        secure_hex_token(4)
    );

    let raw_secret = crate::utils::password::generate_secure_token();
    let secret_hash = hash_password(&raw_secret)?;

    db::oauth2::create_service_client(
        &state.pool,
        &client_id,
        name,
        &body.allowed_scopes,
        user_id,
        &secret_hash,
    )
    .await?;

    Ok(HttpResponse::Created().json(CreateServiceClientResponse {
        client_id,
        client_secret: raw_secret,
        client_name: name.to_string(),
        allowed_scopes: body.allowed_scopes.clone(),
        created_at: Utc::now(),
        warning: "client_secret is shown once and cannot be retrieved again — store it now".into(),
    }))
}

/// `GET /service-clients` — list the caller's own service clients (never the
/// raw secret or its hash).
#[get("/service-clients")]
pub async fn list_my_service_clients(state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    let clients = db::oauth2::list_service_clients_for_user(&state.pool, user_id).await?;
    let summaries: Vec<ServiceClientSummary> = clients
        .into_iter()
        .map(|(client_id, client_name, allowed_scopes, created_at)| ServiceClientSummary {
            client_id,
            client_name,
            allowed_scopes,
            created_at,
        })
        .collect();
    Ok(HttpResponse::Ok().json(summaries))
}

/// `DELETE /service-clients/{client_id}` — revoke one of the caller's own
/// service clients.
#[delete("/service-clients/{client_id}")]
pub async fn revoke_my_service_client(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    db::oauth2::delete_service_client_owned(&state.pool, &path.into_inner(), user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
