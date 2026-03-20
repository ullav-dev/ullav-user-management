use crate::{
    db,
    errors::AppError,
    models::{
        ChangePasswordRequest, ConfirmEmailRequest, LoginRequest, LoginResponse,
        PasswordResetConfirm, PasswordResetRequest,
    },
    utils::{
        app_url::resolve_app_url,
        email::send_password_reset_email,
        jwt::{create_jwt, decode_jwt, Claims},
        password::{generate_secure_token, hash_password, validate_password, verify_password},
    },
    AppState,
};
use actix_web::{get, post, put, web, HttpMessage, HttpRequest, HttpResponse};
use chrono::Utc;
use deadpool_postgres::Pool;
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

    let (roles, permissions) =
        db::get_user_roles_and_permissions(&state.pool, user.id).await?;
    let token = create_jwt(
        user.id,
        &state.jwt_secret,
        state.jwt_ttl_hours,
        roles.clone(),
        permissions.clone(),
    )?;
    let response = LoginResponse {
        token,
        user: user.into(),
        roles,
        permissions,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// `PUT /users/{id}/password` — Change a user's password.
///
/// Requires a valid JWT (injected by `AuthMiddleware`). The caller must either
/// be the owner of the account (`claims.sub == user_id`) or hold the
/// `users:change_any_password` permission. Admins may omit `current_password`;
/// owners must supply it.
#[put("/users/{id}/password")]
pub async fn change_password(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AppError> {
    let user_id = path.into_inner();

    let claims = req
        .extensions()
        .get::<Claims>()
        .ok_or(AppError::InvalidToken)?
        .clone();

    let is_own = claims.sub == user_id.to_string();
    let is_admin = claims.permissions.contains(&"users:change_any_password".to_string());

    if !is_own && !is_admin {
        return Err(AppError::Forbidden);
    }

    validate_password(&body.new_password)?;

    let user = db::get_user_by_id(&state.pool, user_id).await?;

    if is_own {
        let current = body
            .current_password
            .as_deref()
            .ok_or_else(|| AppError::Validation("current_password is required".into()))?;
        let valid = verify_password(current, &user.password_hash)?;
        if !valid {
            return Err(AppError::InvalidCredentials);
        }
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
    let base_url = resolve_app_url(
        body.app_url.as_deref(),
        &state.allowed_app_urls,
        &state.app_base_url,
    )?;

    // Silently ignore unknown emails to prevent enumeration.
    if let Ok(user) = db::get_user_by_email(&state.pool, &body.email).await {
        let token = generate_secure_token();
        db::create_reset_token(&state.pool, user.id, &token, state.reset_token_ttl_minutes)
            .await?;

        if let Some(mailer) = &state.mailer {
            if let Err(e) = send_password_reset_email(
                mailer,
                &state.smtp_from,
                &body.email,
                &base_url,
                &token,
            )
            .await
            {
                log::error!("Failed to send password reset email to {}: {}", body.email, e);
            }
        } else {
            log::info!(
                "Password reset token generated for user {} — token: {}",
                user.id,
                token
            );
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "If the email is registered you will receive a reset token"
    })))
}

/// Shared token-validation logic for both POST and GET confirm-email handlers.
async fn activate_by_token(pool: &Pool, token: &str) -> Result<HttpResponse, AppError> {
    let user = db::get_user_by_confirmation_token(pool, token).await?;

    let expires_at = user.confirmation_token_expires_at.ok_or(AppError::InvalidToken)?;
    if expires_at < Utc::now() {
        return Err(AppError::InvalidToken);
    }

    if !user.is_active {
        db::activate_user(pool, user.id).await?;
    }

    Ok(HttpResponse::NoContent().finish())
}

/// `POST /auth/confirm-email` — Activate a user account using an email confirmation token.
#[post("/auth/confirm-email")]
pub async fn confirm_email(
    state: web::Data<AppState>,
    body: web::Json<ConfirmEmailRequest>,
) -> Result<HttpResponse, AppError> {
    activate_by_token(&state.pool, &body.token).await
}

/// `GET /auth/confirm-email?token=…` — Activate a user account via a link click.
///
/// Email clients fire GET requests when users click links, so this mirrors the
/// POST endpoint but accepts the token as a query parameter.
#[derive(serde::Deserialize)]
struct ConfirmEmailQuery {
    token: String,
}

#[get("/auth/confirm-email")]
pub async fn confirm_email_get(
    state: web::Data<AppState>,
    query: web::Query<ConfirmEmailQuery>,
) -> Result<HttpResponse, AppError> {
    activate_by_token(&state.pool, &query.token).await
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

/// Extract and decode a JWT from the `Authorization: Bearer <token>` header.
///
/// Used by handlers that need to inspect claims but are not covered by middleware.
#[allow(dead_code)]
pub fn extract_claims(req: &HttpRequest, secret: &str) -> Result<Claims, AppError> {
    let header = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::InvalidToken)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(AppError::InvalidToken)?;
    decode_jwt(token, secret)
}
