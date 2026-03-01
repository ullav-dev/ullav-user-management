use crate::{
    db,
    errors::AppError,
    models::CreateUserRequest,
    utils::password::{generate_secure_token, hash_password, validate_password},
    AppState,
};
use actix_web::{post, web, HttpResponse};
use chrono::{Duration, Utc};

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

    let hash = hash_password(&body.password)?;
    let user = db::create_user(&state.pool, &body.email, &body.username, &hash).await?;

    let token = generate_secure_token();
    let expires_at = Utc::now() + Duration::minutes(state.confirmation_token_ttl_minutes);
    db::set_confirmation_token(&state.pool, user.id, &token, expires_at).await?;
    db::assign_role(&state.pool, user.id, "user").await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Account created. Use the confirmation token to activate your account.",
        "confirmation_token": token
    })))
}
