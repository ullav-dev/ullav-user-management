use crate::{
    db,
    errors::AppError,
    models::CreateUserRequest,
    utils::{
        app_url::resolve_app_url,
        email::send_confirmation_email,
        password::{generate_secure_token, hash_password, validate_password},
    },
    AppState,
};
use actix_web::{get, post, web, HttpResponse};
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
