use crate::{
    db,
    errors::AppError,
    models::{CreateUserRequest, UserResponse},
    utils::password::{hash_password, validate_password},
    AppState,
};
use actix_web::{post, web, HttpResponse};

/// `POST /users` — Create a new user account.
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
    let response: UserResponse = user.into();

    Ok(HttpResponse::Created().json(response))
}
