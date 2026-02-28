use crate::{
    db,
    errors::AppError,
    models::{
        ChangePasswordRequest, ConfirmEmailRequest, LoginRequest, LoginResponse,
        PasswordResetConfirm, PasswordResetRequest,
    },
    utils::{
        jwt::create_jwt,
        password::{generate_secure_token, hash_password, validate_password, verify_password},
    },
    AppState,
};
use actix_web::{post, put, web, HttpResponse};
use chrono::Utc;
use uuid::Uuid;

/// `POST /auth/login` — Authenticate a user and return a JWT.
#[post("/auth/login")]
pub async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    let user = db::get_user_by_email(&state.pool, &body.email).await?;

    if !user.is_active {
        return Err(AppError::InvalidCredentials);
    }

    let valid = verify_password(&body.password, &user.password_hash)?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    let token = create_jwt(user.id, &state.jwt_secret, state.jwt_ttl_hours)?;
    let response = LoginResponse {
        token,
        user: user.into(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// `PUT /users/{id}/password` — Change a user's password (authenticated).
#[put("/users/{id}/password")]
pub async fn change_password(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AppError> {
    let user_id = path.into_inner();

    validate_password(&body.new_password)?;

    let user = db::get_user_by_id(&state.pool, user_id).await?;

    let valid = verify_password(&body.current_password, &user.password_hash)?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    let new_hash = hash_password(&body.new_password)?;
    db::update_password(&state.pool, user_id, &new_hash).await?;

    Ok(HttpResponse::NoContent().finish())
}

/// `POST /auth/password-reset/request` — Issue a password-reset token.
///
/// Always returns 200 OK regardless of whether the email exists to prevent
/// user enumeration.
#[post("/auth/password-reset/request")]
pub async fn request_password_reset(
    state: web::Data<AppState>,
    body: web::Json<PasswordResetRequest>,
) -> Result<HttpResponse, AppError> {
    // Silently ignore unknown emails to prevent enumeration.
    if let Ok(user) = db::get_user_by_email(&state.pool, &body.email).await {
        let token = generate_secure_token();
        db::create_reset_token(&state.pool, user.id, &token, state.reset_token_ttl_minutes)
            .await?;

        // In production this token would be emailed to the user.
        // Here we return it in the response body for integration purposes.
        log::info!(
            "Password reset token generated for user {} — token: {}",
            user.id,
            token
        );

        return Ok(HttpResponse::Ok()
            .json(serde_json::json!({ "reset_token": token })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "If the email is registered you will receive a reset token"
    })))
}

/// `POST /auth/confirm-email` — Activate a user account using an email confirmation token.
#[post("/auth/confirm-email")]
pub async fn confirm_email(
    state: web::Data<AppState>,
    body: web::Json<ConfirmEmailRequest>,
) -> Result<HttpResponse, AppError> {
    let user = db::get_user_by_confirmation_token(&state.pool, &body.token).await?;

    let expires_at = user.confirmation_token_expires_at.ok_or(AppError::InvalidToken)?;
    if expires_at < Utc::now() {
        return Err(AppError::InvalidToken);
    }

    if !user.is_active {
        db::activate_user(&state.pool, user.id).await?;
    }

    Ok(HttpResponse::NoContent().finish())
}

/// `POST /auth/password-reset/confirm` — Complete a password reset.
#[post("/auth/password-reset/confirm")]
pub async fn confirm_password_reset(
    state: web::Data<AppState>,
    body: web::Json<PasswordResetConfirm>,
) -> Result<HttpResponse, AppError> {
    validate_password(&body.new_password)?;

    let record = db::get_reset_token(&state.pool, &body.token).await?;

    if record.used || record.expires_at < Utc::now() {
        return Err(AppError::InvalidToken);
    }

    let new_hash = hash_password(&body.new_password)?;
    db::update_password(&state.pool, record.user_id, &new_hash).await?;
    db::consume_reset_token(&state.pool, &body.token).await?;

    Ok(HttpResponse::NoContent().finish())
}
