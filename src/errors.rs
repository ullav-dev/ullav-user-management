use thiserror::Error;

/// Application-level errors.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] tokio_postgres::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),

    #[error("user not found")]
    NotFound,

    #[error("email or username already taken")]
    Conflict,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("token has expired or is invalid")]
    InvalidToken,

    #[error("password hashing error: {0}")]
    Hashing(String),

    #[error("jwt error: {0}")]
    Jwt(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("insufficient permissions")]
    Forbidden,
}

impl actix_web::ResponseError for AppError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict => StatusCode::CONFLICT,
            AppError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AppError::InvalidToken => StatusCode::UNAUTHORIZED,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        let status = self.status_code();
        actix_web::HttpResponse::build(status)
            .json(serde_json::json!({ "error": self.to_string() }))
    }
}
