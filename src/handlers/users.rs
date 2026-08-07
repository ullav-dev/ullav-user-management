use crate::{
    db,
    errors::AppError,
    middleware::auth::claims_from_req,
    models::CreateUserRequest,
    utils::{
        app_url::resolve_app_url,
        email::send_confirmation_email,
        password::{generate_secure_token, hash_password, validate_password},
    },
    AppState,
};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use uuid::Uuid;

/// `POST /users` — Create a new (inactive) user account and return a confirmation token.
#[post("/users")]
pub async fn create_user(
    state: web::Data<AppState>,
    body: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, AppError> {
    validate_password(&body.password)?;

    if body.email.is_empty() || !body.email.contains('@') {
        return Err(AppError::Validation("invalid email address".into()));
    }
    if body.username.is_empty() {
        return Err(AppError::Validation("username must not be empty".into()));
    }

    let base_url = resolve_app_url(
        body.app_url.as_deref(),
        &state.allowed_app_urls,
        &state.app_base_url,
    )?;

    let hash = hash_password(&body.password)?;
    let user = db::create_user(
        &state.pool,
        &body.email,
        &body.username,
        &hash,
        body.first_name.as_deref(),
        body.last_name.as_deref(),
    )
    .await?;

    let token = generate_secure_token();
    let expires_at = Utc::now() + Duration::minutes(state.confirmation_token_ttl_minutes);
    db::set_confirmation_token(&state.pool, user.id, &token, expires_at).await?;
    db::assign_role(&state.pool, user.id, "user").await?;

    if let Some(mailer) = &state.mailer {
        if let Err(e) = send_confirmation_email(
            mailer,
            &state.smtp_from,
            &body.email,
            &base_url,
            &token,
        )
        .await
        {
            log::error!("Failed to send confirmation email to {}: {}", body.email, e);
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Account created. Use the confirmation token to activate your account.",
        "confirmation_token": token
    })))
}

#[derive(Debug, serde::Deserialize)]
pub struct ResolveUsersQuery {
    /// Comma-separated user UUIDs. Unparsable/unknown ids are silently
    /// dropped rather than erroring — callers scan free text (e.g. commit
    /// authorship) for ids that may not resolve to anything.
    pub ids: String,
}

/// `GET /users/resolve?ids=<uuid,uuid,...>` — resolve a batch of user ids to
/// their public username/avatar. Deliberately open to any authenticated
/// user (not admin-gated, unlike `/admin/users`): every caller needing this
/// (lagan's PR/comment/CI-run authorship display, and any similar future
/// use) already sees these users' identity indirectly anyway (e.g. via git
/// commit authorship), so this exposes no new information — only
/// `username`/`avatar_url`, never email or other account details.
#[get("/users/resolve")]
pub async fn resolve_users(
    state: web::Data<AppState>,
    query: web::Query<ResolveUsersQuery>,
) -> Result<HttpResponse, AppError> {
    let ids: Vec<Uuid> = query
        .ids
        .split(',')
        .filter_map(|s| s.trim().parse::<Uuid>().ok())
        .take(200)
        .collect();
    if ids.is_empty() {
        return Ok(HttpResponse::Ok().json(Vec::<db::ResolvedUser>::new()));
    }
    let users = db::resolve_users(&state.pool, &ids).await?;
    Ok(HttpResponse::Ok().json(users))
}

/// `GET /users/{id}/email` — resolve one user's email address. Deliberately
/// separate from `/users/resolve` above, not a widening of it:
/// `/users/resolve` stays open to any caller and never returns email; this
/// endpoint requires authentication and product access, and exists
/// specifically for cunav's "Send as email" to reach an internal reporter
/// (a real UUM user, not the external_reporter_* fields cunav already has
/// for a customer with no account) the same way it already can an external
/// one. Gated on the caller having `cunav` product access on any team
/// (`user_has_product_access`) — not restricted to a shared team with the
/// target user, since a support agent legitimately needs to email any
/// internal reporter a ticket lands in front of them for, not just ones on
/// their own team. Every other product wanting the same capability needs
/// its own product-access check here, not a blanket grant.
#[get("/users/{id}/email")]
pub async fn get_user_email(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let caller_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    if !db::user_has_product_access(&state.pool, caller_id, "cunav").await? {
        return Err(AppError::Forbidden);
    }

    let target_id = path.into_inner();
    let user = db::get_user_by_id(&state.pool, target_id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "email": user.email })))
}
