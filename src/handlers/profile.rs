use crate::{
    db,
    errors::AppError,
    middleware::auth::claims_from_req,
    models::{UpdateProfileRequest, UserResponse},
    AppState,
};
use actix_web::{get, patch, web, HttpRequest, HttpResponse};
use uuid::Uuid;

const AVATAR_URL_MAX_LEN: usize = 2048;

pub fn validate_avatar_url(url: &str) -> Result<(), AppError> {
    if !url.starts_with("https://") {
        return Err(AppError::Validation(
            "avatar_url must use HTTPS".into(),
        ));
    }
    if url.len() > AVATAR_URL_MAX_LEN {
        return Err(AppError::Validation(
            format!("avatar_url must be at most {} characters", AVATAR_URL_MAX_LEN),
        ));
    }
    Ok(())
}

/// `GET /users/me` — return the authenticated user's own profile.
#[get("/users/me")]
pub async fn get_me(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id: Uuid = claims.sub.parse().map_err(|_| AppError::InvalidToken)?;
    let user = db::get_user_by_id(&state.pool, user_id).await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(user)))
}

/// `PATCH /users/me` — update the authenticated user's own profile.
/// Absent fields are left unchanged. `"avatar_url": null` clears the avatar.
#[patch("/users/me")]
pub async fn update_me(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<UpdateProfileRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = claims_from_req(&req)?;
    let user_id: Uuid = claims.sub.parse().map_err(|_| AppError::InvalidToken)?;

    // Validate avatar URL when a new value is being set (not when clearing or omitting).
    if let Some(Some(ref url)) = body.avatar_url {
        validate_avatar_url(url)?;
    }

    let avatar_url = body.avatar_url.as_ref().map(|o| o.as_deref());
    let user = db::update_user_profile(
        &state.pool,
        user_id,
        body.first_name.as_deref(),
        body.last_name.as_deref(),
        avatar_url,
    )
    .await?;

    Ok(HttpResponse::Ok().json(UserResponse::from(user)))
}
